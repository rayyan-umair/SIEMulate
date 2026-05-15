"""
SIEMulate — Sigma Detection Engine
sigma_engine.py — Sigma rule loading, parsing, and event matching

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : Loads Sigma YAML rules from disk via pySigma, compiles them
          into an in-memory rule registry, and evaluates every inbound
          event against all loaded rules. Returns a list of matching
          SigmaRule objects for each event. No alert logic lives here.
          No entity logic lives here. No storage lives here.
          This layer only detects — it does not correlate or score.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/SIEMulate

"Context is the only defense."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Third Party ───────────────────────────────────────────────────────────────
import yaml

try:
    from sigma.rule import SigmaRule as PySigmaRule
    from sigma.collection import SigmaCollection
    from sigma.backends.sqlite import SQLiteBackend
    from sigma.processing.resolver import ProcessingPipelineResolver
    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from database import Database
from models import (
    ChainStage,
    InboundEvent,
    MitreMapping,
    SigmaRule,
)

logger = logging.getLogger(__name__)


# ── MITRE Tag Parser ──────────────────────────────────────────────────────────

def _parse_mitre_from_tags(tags: List[str]) -> MitreMapping:
    """
    Extract MITRE ATT&CK technique and tactic from Sigma rule tags.

    Sigma uses tags like:
        attack.t1059.001   → technique T1059.001
        attack.execution   → tactic Execution
    """
    technique_id   : Optional[str] = None
    technique_name : Optional[str] = None
    tactic         : Optional[str] = None

    for tag in tags:
        tag_lower = tag.lower()

        # Technique — attack.tNNNN or attack.tNNNN.NNN
        if re.match(r"attack\.t\d{4}(\.\d{3})?$", tag_lower):
            raw = tag_lower.replace("attack.", "").upper()
            technique_id = raw

        # Sub-technique
        elif re.match(r"attack\.t\d{4}\.\d{3}$", tag_lower):
            raw = tag_lower.replace("attack.", "").upper()
            technique_id = raw

        # Tactic
        elif tag_lower.startswith("attack.") and not tag_lower[7:].startswith("t"):
            tactic_raw = tag_lower.replace("attack.", "").replace("_", "-")
            tactic = tactic_raw.replace("-", " ").title()

    mitre = MitreMapping(
        technique_id   = technique_id,
        technique_name = technique_name,
        tactic         = tactic,
    )

    # Map tactic → chain stage
    if tactic:
        mitre = MitreMapping.from_tactic(tactic)
        mitre.technique_id   = technique_id
        mitre.technique_name = technique_name

    return mitre


# ── Sigma Level → Severity ────────────────────────────────────────────────────

_LEVEL_SEVERITY: Dict[str, int] = {
    "informational": 1,
    "low"          : 3,
    "medium"       : 5,
    "high"         : 7,
    "critical"     : 10,
}


# ── Condition Evaluator ───────────────────────────────────────────────────────

class ConditionEvaluator:
    """
    Evaluates a compiled Sigma detection block against a flat event dict.

    Supports:
        - field: value         (exact match)
        - field|contains: val  (substring match)
        - field|startswith     (prefix match)
        - field|endswith       (suffix match)
        - field|re             (regex match)
        - field|cidr           (CIDR range — basic)
        - null field checks
        - condition: keywords (selection, filter, 1 of, all of)
        - NOT / AND / OR logic
    """

    def __init__(self, detection: Dict[str, Any], condition: str) -> None:
        self._detection  = detection
        self._condition  = condition.strip()

    def evaluate(self, event_flat: Dict[str, Any]) -> bool:
        """
        Evaluate the detection block against a flat event dictionary.
        Returns True if the condition is satisfied.
        """
        try:
            return self._eval_condition(self._condition, event_flat)
        except Exception as e:
            logger.debug(f"Condition evaluation error: {e}")
            return False

    def _eval_condition(self, condition: str, event: Dict[str, Any]) -> bool:
        """Parse and evaluate a Sigma condition string recursively."""
        condition = condition.strip()

        # ── NOT ───────────────────────────────────────────────────────────────
        if condition.startswith("not "):
            inner = condition[4:].strip()
            return not self._eval_condition(inner, event)

        # ── Parentheses ───────────────────────────────────────────────────────
        if condition.startswith("(") and condition.endswith(")"):
            return self._eval_condition(condition[1:-1], event)

        # ── AND ───────────────────────────────────────────────────────────────
        if " and " in condition.lower():
            parts = re.split(r"\band\b", condition, flags=re.IGNORECASE)
            return all(self._eval_condition(p.strip(), event) for p in parts)

        # ── OR ────────────────────────────────────────────────────────────────
        if " or " in condition.lower():
            parts = re.split(r"\bor\b", condition, flags=re.IGNORECASE)
            return any(self._eval_condition(p.strip(), event) for p in parts)

        # ── 1 of <pattern>* ───────────────────────────────────────────────────
        m = re.match(r"1 of (\w+)\*?", condition, re.IGNORECASE)
        if m:
            prefix = m.group(1).lower()
            keys   = [k for k in self._detection if k.lower().startswith(prefix)]
            return any(self._eval_selection(k, event) for k in keys)

        # ── all of <pattern>* ─────────────────────────────────────────────────
        m = re.match(r"all of (\w+)\*?", condition, re.IGNORECASE)
        if m:
            prefix = m.group(1).lower()
            keys   = [k for k in self._detection if k.lower().startswith(prefix)]
            return all(self._eval_selection(k, event) for k in keys)

        # ── 1 of them ─────────────────────────────────────────────────────────
        if re.match(r"1 of them", condition, re.IGNORECASE):
            keys = [k for k in self._detection if k != "condition"]
            return any(self._eval_selection(k, event) for k in keys)

        # ── all of them ───────────────────────────────────────────────────────
        if re.match(r"all of them", condition, re.IGNORECASE):
            keys = [k for k in self._detection if k != "condition"]
            return all(self._eval_selection(k, event) for k in keys)

        # ── Named selection identifier ────────────────────────────────────────
        if condition in self._detection:
            return self._eval_selection(condition, event)

        # ── filter modifier: selection and not filter ─────────────────────────
        m = re.match(r"(\w+) and not (\w+)", condition, re.IGNORECASE)
        if m:
            sel    = m.group(1)
            filt   = m.group(2)
            sel_ok = self._eval_selection(sel, event) if sel in self._detection else False
            flt_ok = self._eval_selection(filt, event) if filt in self._detection else False
            return sel_ok and not flt_ok

        return False

    def _eval_selection(
        self,
        selection_key: str,
        event        : Dict[str, Any],
    ) -> bool:
        """Evaluate a named selection block against the event."""
        block = self._detection.get(selection_key)
        if block is None:
            return False

        # List of dicts → OR across list items
        if isinstance(block, list):
            return any(self._eval_mapping(item, event) for item in block)

        # Single dict
        if isinstance(block, dict):
            return self._eval_mapping(block, event)

        return False

    def _eval_mapping(
        self,
        mapping: Dict[str, Any],
        event  : Dict[str, Any],
    ) -> bool:
        """
        Evaluate a field mapping block.
        All fields in the mapping must match (implicit AND).
        """
        for field_expr, expected in mapping.items():
            if not self._eval_field(field_expr, expected, event):
                return False
        return True

    def _eval_field(
        self,
        field_expr: str,
        expected  : Any,
        event     : Dict[str, Any],
    ) -> bool:
        """
        Evaluate a single field expression against the event.
        Handles: contains, startswith, endswith, re, cidr, null modifiers.
        """
        # Parse field and modifier
        parts    = field_expr.split("|")
        field    = parts[0].strip()
        modifier = parts[1].strip().lower() if len(parts) > 1 else "exact"

        # Get actual value from event — case-insensitive key lookup
        actual = None
        for key, val in event.items():
            if key.lower() == field.lower():
                actual = val
                break

        # null check
        if modifier == "null":
            return actual is None

        if actual is None:
            return False

        actual_str = str(actual).lower()

        # Normalize expected to list for uniform processing
        if not isinstance(expected, list):
            expected = [expected]

        for exp in expected:
            exp_str = str(exp).lower()

            if modifier == "exact" or modifier == "":
                if actual_str == exp_str:
                    return True

            elif modifier == "contains":
                if exp_str in actual_str:
                    return True

            elif modifier == "contains|all":
                # All values must be present
                if all(e.lower() in actual_str for e in expected):
                    return True

            elif modifier == "startswith":
                if actual_str.startswith(exp_str):
                    return True

            elif modifier == "endswith":
                if actual_str.endswith(exp_str):
                    return True

            elif modifier == "re":
                try:
                    if re.search(exp_str, actual_str, re.IGNORECASE):
                        return True
                except re.error:
                    pass

            elif modifier == "cidr":
                try:
                    import ipaddress
                    network = ipaddress.ip_network(exp_str, strict=False)
                    addr    = ipaddress.ip_address(actual_str)
                    if addr in network:
                        return True
                except ValueError:
                    pass

            elif modifier == "windash":
                # Windows command-line dash/slash normalization
                normalized = actual_str.replace("-", "/")
                if exp_str.replace("-", "/") in normalized:
                    return True

        return False


# ── Rule Loader ───────────────────────────────────────────────────────────────

def _load_rule_from_yaml(path: Path) -> Optional[SigmaRule]:
    """
    Parse a single Sigma YAML file into a SigmaRule model.
    Returns None if the file is invalid or unsupported.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            logger.debug(f"Skipping non-dict YAML: {path.name}")
            return None

        title = raw.get("title", path.stem)
        if not title:
            return None

        tags      = raw.get("tags", []) or []
        mitre     = _parse_mitre_from_tags(tags)
        detection = raw.get("detection", {}) or {}
        condition = ""

        if isinstance(detection, dict):
            condition = str(detection.get("condition", ""))

        rule = SigmaRule(
            title       = title,
            description = raw.get("description", ""),
            author      = raw.get("author"),
            status      = raw.get("status", "experimental"),
            level       = raw.get("level", "medium"),
            tags        = tags,
            mitre       = mitre,
            logsource   = raw.get("logsource", {}) or {},
            detection   = detection,
            condition   = condition,
            fields      = raw.get("fields", []) or [],
            file_path   = str(path),
            loaded_at   = datetime.now(timezone.utc),
        )
        return rule

    except yaml.YAMLError as e:
        logger.warning(f"YAML parse error in {path.name}: {e}")
        return None
    except Exception as e:
        logger.warning(f"Failed to load rule {path.name}: {e}")
        return None


# ── Sigma Engine ──────────────────────────────────────────────────────────────

class SigmaEngine:
    """
    The detection layer of SIEMulate.

    Loads all Sigma YAML rules from the rules directory, compiles
    each into a ConditionEvaluator, and evaluates every inbound
    event against all loaded rules.

    Rules are hot-reloaded on a configurable interval — no restart
    required after adding or modifying rules.

    Thread safety: a single lock protects the rule registry.
    Rule reload happens in the background without blocking detection.

    Usage:
        engine = SigmaEngine(settings, db)
        engine.load_rules()
        matches = engine.evaluate(event)
    """

    def __init__(self, settings: Settings, db: Database) -> None:
        self._settings   = settings
        self._db         = db
        self._lock       = threading.RLock()

        # Rule registry: rule_id → (SigmaRule, ConditionEvaluator)
        self._rules      : Dict[str, Tuple[SigmaRule, ConditionEvaluator]] = {}
        self._loaded_at  : Optional[datetime] = None
        self._eval_count = 0
        self._match_count= 0

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def load_rules(self) -> int:
        """
        Load all Sigma YAML rules from the rules directory.
        Persists each rule to DuckDB.
        Returns the number of rules successfully loaded.
        """
        rules_path = Path(self._settings.rules_dir)
        if not rules_path.exists():
            logger.warning(
                f"Rules directory not found: {rules_path}. "
                f"Create it and add Sigma YAML files."
            )
            return 0

        yaml_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
        if not yaml_files:
            logger.warning(
                f"No Sigma YAML files found in {rules_path}. "
                f"Download rules from https://github.com/SigmaHQ/sigma"
            )
            return 0

        loaded   = 0
        failed   = 0
        new_rules: Dict[str, Tuple[SigmaRule, ConditionEvaluator]] = {}

        for path in yaml_files:
            rule = _load_rule_from_yaml(path)
            if rule is None:
                failed += 1
                continue

            evaluator = ConditionEvaluator(rule.detection, rule.condition)
            new_rules[rule.rule_id] = (rule, evaluator)

            try:
                self._db.upsert_rule(rule)
            except Exception as e:
                logger.debug(f"Rule persist failed for {rule.title}: {e}")

            loaded += 1

        with self._lock:
            self._rules     = new_rules
            self._loaded_at = datetime.now(timezone.utc)

        logger.info(
            f"Sigma rules loaded: {loaded} ok, {failed} failed "
            f"from {rules_path}"
        )
        return loaded

    def reload_rules(self) -> int:
        """Hot-reload rules from disk — called by the background scheduler."""
        logger.debug("Hot-reloading Sigma rules...")
        return self.load_rules()

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate(self, event: InboundEvent) -> List[SigmaRule]:
        """
        Evaluate an inbound event against all loaded Sigma rules.
        Returns a list of SigmaRule objects that matched.
        Never raises — evaluation errors are caught per-rule.
        """
        if not self._settings.rules_enabled:
            return []

        self._eval_count += 1

        # Flatten the event into a single dict for field matching
        flat = self._flatten_event(event)

        matched: List[SigmaRule] = []

        with self._lock:
            rules_snapshot = list(self._rules.values())

        for rule, evaluator in rules_snapshot:
            if not rule.enabled:
                continue
            try:
                if evaluator.evaluate(flat):
                    rule.match_count += 1
                    self._match_count += 1
                    matched.append(rule)
                    logger.debug(
                        f"Rule matched: '{rule.title}' "
                        f"on entity '{event.entity.name}'"
                    )
            except Exception as e:
                logger.debug(f"Rule '{rule.title}' evaluation error: {e}")

        return matched

    def _flatten_event(self, event: InboundEvent) -> Dict[str, Any]:
        """
        Flatten an InboundEvent into a single-level dict for Sigma matching.
        Sigma rules reference fields by name — the flat dict maps all
        nested event fields to top-level keys for uniform matching.
        """
        flat: Dict[str, Any] = {}

        # Top-level
        flat["event_id"]   = event.event_id
        flat["timestamp"]  = event.timestamp.isoformat()
        flat["source"]     = event.source.value

        # Entity
        flat["user"]           = event.entity.name
        flat["username"]       = event.entity.name
        flat["src_user"]       = event.entity.name
        flat["host"]           = event.entity.host or ""
        flat["hostname"]       = event.entity.host or ""
        flat["computer"]       = event.entity.host or ""
        flat["workstation"]    = event.entity.host or ""
        flat["entity_type"]    = event.entity.type.value
        flat["domain"]         = event.entity.domain or ""

        # Event context
        flat["event_type"]     = event.event.type.value
        flat["action"]         = event.event.action or ""
        flat["severity"]       = event.event.severity
        flat["outcome"]        = event.event.outcome or ""

        # MITRE
        flat["technique"]      = event.mitre.technique_id or ""
        flat["tactic"]         = event.mitre.tactic or ""

        # Raw payload — merge all keys to top level for field matching
        for key, val in event.raw_payload.items():
            if key not in flat:
                flat[key] = val

            # Common Windows Event Log field aliases
            if key.lower() == "eventid":
                flat["EventID"]      = val
                flat["event_id_win"] = val
            if key.lower() == "commandline":
                flat["CommandLine"]  = val
                flat["cmd"]          = val
            if key.lower() == "imagepath":
                flat["Image"]        = val
                flat["process"]      = val
            if key.lower() == "parentimage":
                flat["ParentImage"]  = val
            if key.lower() == "targetusername":
                flat["TargetUserName"] = val
                flat["user"]           = val
            if key.lower() == "ipaddress":
                flat["IpAddress"]    = val
                flat["src_ip"]       = val
            if key.lower() == "destinationport":
                flat["dst_port"]     = val
                flat["DestinationPort"] = val

        return flat

    # ── Rule Management ───────────────────────────────────────────────────────

    def get_rule(self, rule_id: str) -> Optional[SigmaRule]:
        with self._lock:
            entry = self._rules.get(rule_id)
            return entry[0] if entry else None

    def get_all_rules(self) -> List[SigmaRule]:
        with self._lock:
            return [rule for rule, _ in self._rules.values()]

    def enable_rule(self, rule_id: str) -> bool:
        with self._lock:
            if rule_id in self._rules:
                self._rules[rule_id][0].enabled = True
                return True
            return False

    def disable_rule(self, rule_id: str) -> bool:
        with self._lock:
            if rule_id in self._rules:
                self._rules[rule_id][0].enabled = False
                return True
            return False

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        with self._lock:
            enabled = sum(1 for r, _ in self._rules.values() if r.enabled)
        return {
            "rules_loaded"   : len(self._rules),
            "rules_enabled"  : enabled,
            "events_evaluated": self._eval_count,
            "total_matches"  : self._match_count,
            "loaded_at"      : self._loaded_at.isoformat() if self._loaded_at else None,
            "pysigma_available": PYSIGMA_AVAILABLE,
        }