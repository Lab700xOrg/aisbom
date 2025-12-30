import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
import re

@dataclass
class ComponentDiff:
    name: str
    version_diff: Optional[Tuple[str, str]] = None
    hash_diff: Optional[Tuple[str, str]] = None
    risk_diff: Optional[Tuple[str, str]] = None
    legal_status_diff: Optional[Tuple[str, str]] = None
    license_diff: Optional[Tuple[str, str]] = None

@dataclass
class DiffResult:
    added: List[dict] = field(default_factory=list)
    removed: List[dict] = field(default_factory=list)
    changed: List[ComponentDiff] = field(default_factory=list)
    risk_increased: bool = False
    hash_drifted: bool = False

class SBOMDiff:
    RISK_LEVELS = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def __init__(self, old_path: Path, new_path: Path):
        self.old_data = self._load(old_path)
        self.new_data = self._load(new_path)

    def _load(self, path: Path) -> dict:
        with open(path, "rb") as f:
            return json.load(f)

    def _get_risk(self, component: dict) -> str:
        desc = component.get("description", "")
        if not desc:
            return "UNKNOWN"
        match = re.search(r"Risk:\s*([A-Z]+)", desc)
        return match.group(1) if match else "UNKNOWN"

    def _get_hash(self, component: dict) -> str:
        hashes = component.get("hashes", [])
        if not hashes:
            return ""
        for h in hashes:
            if h.get("alg") == "SHA-256":
                return h.get("content")
        return ""

    def _get_license(self, component: dict) -> str:
        desc = component.get("description", "")
        if not desc:
            return "Unknown"
        # Parse "License: ..."
        match = re.search(r"License:\s*([^|]+)", desc)
        return match.group(1).strip() if match else "Unknown"

    def _get_legal_status(self, component: dict) -> str:
        # Legal: LEGAL RISK (cc...) or UNKNOWN or PASS
        desc = component.get("description", "")
        if not desc:
            return "UNKNOWN"
        match = re.search(r"Legal:\s*([^|]+)", desc)
        if not match:
            return "UNKNOWN"
        
        val = match.group(1).strip()
        # Clean up formatting if it has nested parens or trailing pipes (though regex excludes pipe)
        # If value is "LEGAL RISK (cc-by-nc...)", we might just want the status "LEGAL RISK" or the whole thing?
        # User wants level of risk. So let's extract the main label.
        if val.startswith("LEGAL RISK"):
            return "LEGAL RISK"
        if val.startswith("PASS"):
            return "PASS"
        if val.startswith("UNKNOWN"):
            return "UNKNOWN"
        return val

    def compare(self) -> DiffResult:
        old_comps = {c["name"]: c for c in self.old_data.get("components", [])}
        new_comps = {c["name"]: c for c in self.new_data.get("components", [])}

        result = DiffResult()

        for name in new_comps:
            if name not in old_comps:
                result.added.append(new_comps[name])
                # Check if added component is CRITICAL
                if self._get_risk(new_comps[name]) == "CRITICAL":
                    result.risk_increased = True
            else:
                # Compare
                old_c = old_comps[name]
                new_c = new_comps[name]
                diff = ComponentDiff(name=name)
                has_change = False

                # Version
                old_ver = old_c.get("version", "unknown")
                new_ver = new_c.get("version", "unknown")
                if old_ver != new_ver:
                    diff.version_diff = (old_ver, new_ver)
                    has_change = True

                # Hash
                old_hash = self._get_hash(old_c)
                new_hash = self._get_hash(new_c)
                if old_hash != new_hash and old_hash and new_hash:
                    # Only flag drift if both have hashes (avoid flagging 'added hash' as drift, though maybe we should?)
                    # Requirement says "Model Hash Drift".
                    diff.hash_diff = (old_hash, new_hash)
                    result.hash_drifted = True
                    has_change = True
                
                # Risk
                old_risk = self._get_risk(old_c)
                new_risk = self._get_risk(new_c)
                
                if old_risk != new_risk:
                    diff.risk_diff = (old_risk, new_risk)
                    has_change = True
                    
                    old_score = self.RISK_LEVELS.get(old_risk, 0)
                    new_score = self.RISK_LEVELS.get(new_risk, 0)
                    
                    # Logic: If it worsened OR if it is now CRITICAL (regardless of old, though old != new so assumedly worse if new is CRITICAL)
                    if new_score > old_score:
                        # Worsened
                        pass
                    
                    if new_risk == "CRITICAL":
                        result.risk_increased = True

                # Legal Status Diff
                old_status = self._get_legal_status(old_c)
                new_status = self._get_legal_status(new_c)
                if old_status != new_status:
                    diff.legal_status_diff = (old_status, new_status)
                    has_change = True

                # License Name Diff
                old_lic = self._get_license(old_c)
                new_lic = self._get_license(new_c)
                if old_lic != new_lic:
                    diff.license_diff = (old_lic, new_lic)
                    has_change = True

                if has_change:
                    result.changed.append(diff)

        for name in old_comps:
            if name not in new_comps:
                result.removed.append(old_comps[name])

        return result
