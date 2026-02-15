import argparse
import json
import os
import re
import shutil
from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple, List

TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Common MITRE STIX flags (varies slightly by dataset version)
DEPRECATED_KEYS = ("deprecated", "x_mitre_deprecated")
REVOKED_KEYS = ("revoked", "x_mitre_revoked")


@dataclass(frozen=True)
class StatusSets:
    active: Set[str]
    deprecated: Set[str]
    revoked: Set[str]


def load_status_sets(enterprise_attack_json: str) -> StatusSets:
    """
    Build sets of technique IDs (including sub-techniques) that are active, deprecated, revoked.
    Uses the official STIX flags in enterprise-attack.json.
    """
    with open(enterprise_attack_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    objs = data.get("objects")
    if not isinstance(objs, list):
        raise ValueError("enterprise-attack.json does not contain an 'objects' array. Wrong file?")

    active: Set[str] = set()
    deprecated: Set[str] = set()
    revoked: Set[str] = set()

    def is_true(obj: dict, keys: Tuple[str, ...]) -> bool:
        for k in keys:
            if obj.get(k) is True:
                return True
        return False

    def extract_attack_id(obj: dict) -> Optional[str]:
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                return str(ref["external_id"]).upper()
        return None

    for obj in objs:
        if obj.get("type") != "attack-pattern":
            continue

        tid = extract_attack_id(obj)
        if not tid:
            continue

        # Determine status
        is_revoked = is_true(obj, REVOKED_KEYS)
        is_depr = is_true(obj, DEPRECATED_KEYS)

        if is_revoked:
            revoked.add(tid)
        elif is_depr:
            deprecated.add(tid)
        else:
            active.add(tid)

    return StatusSets(active=active, deprecated=deprecated, revoked=revoked)


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def extract_tech_id_from_md(md_path: str) -> Optional[str]:
    """
    Try hard to extract the technique ID from the markdown file:
    - Prefer metadata: "Technique ID: Txxxx(.xxx)"
    - Else first H1 header containing Txxxx
    - Else any technique ID in file (first match)
    """
    text = read_text(md_path)

    # 1) Metadata line
    m = re.search(r"(?im)^\s*(?:-?\s*)Technique\s+ID\s*:\s*(T\d{4}(?:\.\d{3})?)\s*$", text)
    if m:
        return m.group(1).upper()

    # 2) First H1 containing an ID
    h1 = re.search(r"(?m)^\s*#\s+(.+)\s*$", text)
    if h1:
        m2 = TECH_ID_RE.search(h1.group(1))
        if m2:
            return m2.group(0).upper()

    # 3) First ID anywhere
    m3 = TECH_ID_RE.search(text)
    if m3:
        return m3.group(0).upper()

    return None


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def safe_copy(src: str, dst_dir: str) -> str:
    ensure_dir(dst_dir)
    base = os.path.basename(src)
    dst = os.path.join(dst_dir, base)

    # Avoid overwrite by appending counter if needed
    if not os.path.exists(dst):
        shutil.copy2(src, dst)
        return dst

    name, ext = os.path.splitext(base)
    i = 2
    while True:
        candidate = os.path.join(dst_dir, f"{name}__{i}{ext}")
        if not os.path.exists(candidate):
            shutil.copy2(src, candidate)
            return candidate
        i += 1


def classify_and_copy(
    kb_in: str,
    kb_active_out: str,
    kb_revoked_depr_out: str,
    kb_unknown_out: str,
    status_sets: StatusSets,
) -> Tuple[int, int, int, int]:
    """
    Walk kb_in and copy .md files into target folders based on technique status.
    Returns counts: (total_md, active_copied, revoked_or_depr_copied, unknown_copied)
    """
    total_md = 0
    active_c = 0
    bad_c = 0
    unknown_c = 0

    for root, _, files in os.walk(kb_in):
        for fn in files:
            if not fn.lower().endswith(".md"):
                continue
            total_md += 1
            path = os.path.join(root, fn)

            tid = extract_tech_id_from_md(path)
            if not tid:
                safe_copy(path, kb_unknown_out)
                unknown_c += 1
                continue

            if tid in status_sets.revoked or tid in status_sets.deprecated:
                safe_copy(path, kb_revoked_depr_out)
                bad_c += 1
            elif tid in status_sets.active:
                safe_copy(path, kb_active_out)
                active_c += 1
            else:
                # Technique ID not found in the enterprise dataset (could be mobile/ics, or custom)
                safe_copy(path, kb_unknown_out)
                unknown_c += 1

    return total_md, active_c, bad_c, unknown_c


def write_report(
    report_path: str,
    kb_in: str,
    status_sets: StatusSets,
) -> None:
    """
    Write a simple CSV report mapping each md file -> extracted technique id -> status.
    """
    rows: List[str] = ["file_path,technique_id,status"]
    for root, _, files in os.walk(kb_in):
        for fn in files:
            if not fn.lower().endswith(".md"):
                continue
            path = os.path.join(root, fn)
            tid = extract_tech_id_from_md(path)
            if not tid:
                status = "unknown_no_id"
            elif tid in status_sets.revoked:
                status = "revoked"
            elif tid in status_sets.deprecated:
                status = "deprecated"
            elif tid in status_sets.active:
                status = "active"
            else:
                status = "unknown_not_in_enterprise_attack_json"

            # CSV-escape path
            p = path.replace('"', '""')
            t = (tid or "").replace('"', '""')
            rows.append(f"\"{p}\",\"{t}\",\"{status}\"")

    ensure_dir(os.path.dirname(report_path) or ".")
    with open(report_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(rows))


def main():
    ap = argparse.ArgumentParser(
        description="Split an ATT&CK markdown KB into ACTIVE vs REVOKED/DEPRECATED using enterprise-attack.json."
    )
    ap.add_argument("--kb-in", required=True, help=r"Source KB folder, e.g. C:\ai-kb\kb_out")
    ap.add_argument("--enterprise-json", required=True, help=r"Path to enterprise-attack.json")
    ap.add_argument("--out-root", required=True, help=r"Output root folder, e.g. C:\ai-kb\kb_split")
    ap.add_argument("--report", default=None, help=r"Optional CSV report path, e.g. C:\ai-kb\kb_split\report.csv")

    args = ap.parse_args()

    status_sets = load_status_sets(args.enterprise_json)

    kb_active_out = os.path.join(args.out_root, "active")
    kb_bad_out = os.path.join(args.out_root, "revoked_or_deprecated")
    kb_unknown_out = os.path.join(args.out_root, "unknown")

    total_md, active_c, bad_c, unknown_c = classify_and_copy(
        kb_in=args.kb_in,
        kb_active_out=kb_active_out,
        kb_revoked_depr_out=kb_bad_out,
        kb_unknown_out=kb_unknown_out,
        status_sets=status_sets,
    )

    if args.report:
        write_report(args.report, args.kb_in, status_sets)

    print("Done.")
    print(f"Source .md files found: {total_md}")
    print(f"Copied ACTIVE: {active_c}  -> {kb_active_out}")
    print(f"Copied REVOKED/DEPRECATED: {bad_c}  -> {kb_bad_out}")
    print(f"Copied UNKNOWN: {unknown_c}  -> {kb_unknown_out}")
    if args.report:
        print(f"CSV report: {args.report}")


if __name__ == "__main__":
    main()
