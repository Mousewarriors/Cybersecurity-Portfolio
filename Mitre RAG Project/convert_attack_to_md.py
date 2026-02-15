#!/usr/bin/env python3
r"""
Convert MITRE ATT&CK enterprise-attack.json (STIX bundle) into one Markdown file per technique/sub-technique,
optimized for Open WebUI Knowledge Base vector search (query_knowledge_files / File Context).

Enhancement vs prior version:
- Auto-injects "log-like" keywords (executables, flags, API strings, code tags, registry paths, event IDs, etc.)
- Adds a "Log Indicators" section to each file (simple, schema-like strings that match alerts/logs)

Defaults:
  Input : C:\ai-kb\attack\enterprise-attack.json
  Output: C:\ai-kb\attack\attack_md

No third-party dependencies (stdlib only).
"""

import json
import os
import re
import textwrap
import argparse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_INPUT = r"C:\ai-kb\attack\enterprise-attack.json"
DEFAULT_OUTPUT = r"C:\ai-kb\attack\attack_md"

INCLUDE_PARENT_FOR_SUBTECHNIQUES = True
MAX_KEYWORDS = 35
MAX_LOG_INDICATORS = 12


# -----------------------------
# Helpers
# -----------------------------
def _sanitize_filename(s: str) -> str:
    s = re.sub(r"[^\w\s\-.]", "", s, flags=re.UNICODE)
    s = re.sub(r"\s+", "_", s.strip())
    return s[:120] if len(s) > 120 else s


def _norm_space(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def _wrap_md(s: str, width: int = 100) -> str:
    lines = (s or "").splitlines()
    out = []
    buf: List[str] = []
    for line in lines:
        if not line.strip():
            if buf:
                out.append(textwrap.fill(" ".join(buf), width=width))
                buf = []
            out.append("")
        else:
            buf.append(line.strip())
    if buf:
        out.append(textwrap.fill(" ".join(buf), width=width))
    return "\n".join(out).strip()


def _dedupe_preserve(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        x = _norm_space(x)
        if not x:
            continue
        k = x.lower()
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


# -----------------------------
# ATT&CK field extraction
# -----------------------------
def _get_external_id_and_url(obj: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") in ("mitre-attack", "mitre-enterprise"):
            ext_id = ref.get("external_id")
            url = ref.get("url")
            if ext_id:
                return str(ext_id), (str(url) if url else None)

    for ref in obj.get("external_references", []) or []:
        ext_id = ref.get("external_id")
        url = ref.get("url")
        if ext_id:
            return str(ext_id), (str(url) if url else None)

    return None, None


def _extract_kill_chain_tactics(obj: Dict[str, Any]) -> List[str]:
    tactics = []
    for phase in obj.get("kill_chain_phases", []) or []:
        pn = phase.get("phase_name")
        if pn:
            tactics.append(pn.replace("-", " ").title())
    return _dedupe_preserve(tactics)


def _extract_list(obj: Dict[str, Any], key: str) -> List[str]:
    val = obj.get(key)
    if not val:
        return []
    if isinstance(val, list):
        return [str(x) for x in val if str(x).strip()]
    if isinstance(val, str):
        return [val]
    return []


def _build_subtechnique_parent_map(objects: List[Dict[str, Any]]) -> Dict[str, str]:
    m: Dict[str, str] = {}
    for o in objects:
        if o.get("type") != "relationship":
            continue
        if o.get("relationship_type") != "subtechnique-of":
            continue
        src = o.get("source_ref")
        tgt = o.get("target_ref")
        if src and tgt:
            m[str(src)] = str(tgt)
    return m


# -----------------------------
# Keyword + log-indicator injection
# -----------------------------
def _extract_log_like_terms(text: str) -> List[str]:
    """
    Pull log-like indicators from ATT&CK text:
    - executables: powershell.exe, cmd.exe, rundll32.exe, etc.
    - flags/switches: -enc, -nop, /create
    - registry paths: HKLM\..., HKEY_LOCAL_MACHINE\...
    - event IDs: Event ID 4688, Sysmon 1, etc.
    - code fragments: Start-Process, Invoke-Command, FromBase64String, WMI classes, DLLs
    """
    if not text:
        return []
    t = text

    terms: List[str] = []

    # HTML <code>...</code> blocks often contain cmdlets / function names
    for m in re.findall(r"<code>(.*?)</code>", t, flags=re.IGNORECASE | re.DOTALL):
        s = _norm_space(re.sub(r"<.*?>", "", m))
        # split on whitespace but keep "Start-Process" etc.
        for tok in re.findall(r"[A-Za-z0-9_.:-]{3,}", s):
            terms.append(tok)

    # Executables / DLLs
    for tok in re.findall(r"\b[A-Za-z0-9_-]{2,}\.(exe|dll|ps1|bat|cmd|vbs|js|jar)\b", t, flags=re.IGNORECASE):
        pass  # (we capture below with full match)

    for exe in re.findall(r"\b[A-Za-z0-9_-]{2,}\.(?:exe|dll|ps1|bat|cmd|vbs|js|jar)\b", t, flags=re.IGNORECASE):
        terms.append(exe)

    # Registry paths (common forms)
    for rp in re.findall(r"\bHK(?:LM|CU|CR|U|CC)\\[A-Za-z0-9_\\\- .]{4,}", t, flags=re.IGNORECASE):
        terms.append(rp)
    for rp in re.findall(r"\bHKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[A-Za-z0-9_\\\- .]{4,}", t, flags=re.IGNORECASE):
        terms.append(rp)

    # Command switches: -enc, -nop, /create, /sc
    # keep short but meaningful
    for sw in re.findall(r"(?<!\w)(?:-{1,2}[A-Za-z][A-Za-z0-9_-]{1,15}|/[A-Za-z]{2,12})(?!\w)", t):
        if sw.lower() in ("-and", "-or", "-not"):
            continue
        terms.append(sw)

    # Event IDs like 4688, "Event ID 4688", "Sysmon Event ID 1"
    for eid in re.findall(r"\b(?:Event\s*ID|EventID|Sysmon\s*(?:Event\s*ID|ID)?)\s*[:=]?\s*(\d{1,5})\b", t, flags=re.IGNORECASE):
        terms.append(f"EventID {eid}")

    # .NET / namespaces / API-ish strings
    for api in re.findall(r"\b[A-Za-z0-9_]+\.[A-Za-z0-9_.]+\b", t):
        # avoid overly-generic sentence artifacts by requiring at least one dot and min length
        if len(api) >= 12 and api.count(".") >= 1:
            terms.append(api)

    # Common LOLBin-style invocations: "cmd.exe /c", "powershell.exe -enc"
    for m in re.findall(r"\b([A-Za-z0-9_-]{2,}\.exe)\b\s+([-/][A-Za-z0-9_-]{1,12})\b", t, flags=re.IGNORECASE):
        terms.append(f"{m[0]} {m[1]}")

    return _dedupe_preserve(terms)


def _domain_boosters(technique_id: str, name: str, description: str) -> List[str]:
    """
    Very small, non-complicated boosters that dramatically improve alert matching.
    This is NOT a complex tool—just a few static additions for common log patterns.
    """
    n = (name or "").lower()
    d = (description or "").lower()
    out: List[str] = []

    def add(*xs: str):
        for x in xs:
            if x:
                out.append(x)

    # PowerShell
    if "powershell" in n or "powershell" in d:
        add("powershell.exe", "pwsh", "-enc", "encodedcommand", "-EncodedCommand",
            "-nop", "-NoProfile", "-w hidden", "-WindowStyle Hidden",
            "-ExecutionPolicy", "Bypass", "-Command",
            "FromBase64String", "Invoke-Expression", "IEX",
            "Invoke-WebRequest", "iwr", "DownloadString", "Net.WebClient",
            "ScriptBlockLogging", "System.Management.Automation")

    # Windows Command Shell / cmd
    if "windows command shell" in n or re.search(r"\bcmd\b", n):
        add("cmd.exe", "/c", "/q", "/v", "comspec")

    # Rundll32
    if "rundll32" in n or "rundll32" in d:
        add("rundll32.exe", "Control_RunDLL")

    # WMI
    if "windows management instrumentation" in n or "wmi" in n or "wmic" in d:
        add("wmic.exe", "Win32_Process", "process call create")

    # Scheduled Tasks
    if "scheduled task" in n or "scheduled tasks" in d:
        add("schtasks.exe", "/create", "/run", "/sc", "/tn", "/tr")

    # Registry modification
    if "registry" in n or "registry" in d:
        add("reg.exe", "reg add", "reg delete", "HKLM\\", "HKCU\\")

    # Obfuscation (often paired with PowerShell / JS)
    if technique_id.startswith("T1027") or "obfus" in n or "obfus" in d:
        add("base64", "FromBase64String", "gzip", "deflate", "xor")

    return _dedupe_preserve(out)


def _compose_keywords(
    technique_id: str,
    name: str,
    tactics: List[str],
    platforms: List[str],
    data_sources: List[str],
    aliases: List[str],
    description: str,
    detection: str,
) -> List[str]:
    """
    Build a keyword list that is:
    - RAG-friendly (short, explicit)
    - Alert/log-friendly (executables, flags, APIs)
    """
    kws: List[str] = []

    # Always anchor with ID + name
    kws.extend([technique_id, name])

    # Helpful environment anchors
    kws.extend(tactics)
    kws.extend(platforms)

    # Aliases (if present)
    kws.extend(aliases[:10])

    # Data sources (these help queries like "process creation", etc.)
    kws.extend(data_sources[:12])

    # Extract log-like terms from the ATT&CK text itself
    kws.extend(_extract_log_like_terms(description))
    kws.extend(_extract_log_like_terms(detection))

    # Add a few tiny domain boosters (kept intentionally small/simple)
    kws.extend(_domain_boosters(technique_id, name, description))

    # Dedupe + cap
    kws = _dedupe_preserve(kws)

    # Trim obviously-too-generic terms that hurt retrieval
    drop = {"windows", "execution", "technique", "adversaries", "adversary"}
    kws = [k for k in kws if k.lower() not in drop]

    # Drop URL/path junk (improves precision)
    bad_substrings = ("attack.mitre.org", "http://", "https://")
    kws = [k for k in kws if not any(b in k.lower() for b in bad_substrings)]
    kws = [k for k in kws if not re.fullmatch(r"/[a-z0-9_-]{2,}", k, flags=re.I)]

    return kws[:MAX_KEYWORDS]


def _compose_log_indicators(name: str, platforms: List[str], keywords: List[str]) -> List[str]:
    """
    Emit simple schema-like indicators that match typical alert fields.
    We infer exe names + a few high-signal switches from keywords.
    """
    inds: List[str] = []
    plat = "windows" if any(p.lower() == "windows" for p in platforms) else ""

    # Collect executables found in keywords
    exes = [k for k in keywords if re.search(r"\b[A-Za-z0-9_-]{2,}\.exe\b", k, flags=re.I)]
    exes = _dedupe_preserve(exes)[:3]

    switches = [k for k in keywords if re.fullmatch(r"(-{1,2}[A-Za-z][A-Za-z0-9_-]{1,15}|/[A-Za-z]{2,12})", k)]
    switches = _dedupe_preserve(switches)[:4]

    apis = [k for k in keywords if k.count(".") >= 1 and len(k) >= 12]
    apis = _dedupe_preserve(apis)[:2]

    # Generic fields that are widely used
    if plat == "windows":
        inds.append("process.name")
        inds.append("process.command_line")
        inds.append("process.parent.name")
        inds.append("event.id=4688  # Windows Security Process Creation (if enabled)")
        inds.append("sysmon.event_id=1  # Sysmon Process Create (if deployed)")

    # Specific exe indicators
    for exe in exes:
        inds.append(f"process.name={exe}")

    # Switch indicators
    for sw in switches:
        inds.append(f"process.command_line contains {sw}")

    # API/string indicators
    for api in apis:
        inds.append(f"process.command_line contains {api}")

    # PowerShell-specific field hints (very common)
    if "powershell" in (name or "").lower() or any(k.lower() in ("powershell.exe", "pwsh") for k in keywords):
        inds.append("powershell.script_block_logging  # if enabled")
        inds.append("powershell.module_logging       # if enabled")

    inds = _dedupe_preserve(inds)
    return inds[:MAX_LOG_INDICATORS]


# -----------------------------
# Markdown writer
# -----------------------------
def _write_md_file(
    out_dir: str,
    technique_id: str,
    name: str,
    url: Optional[str],
    is_sub: bool,
    parent_ext_id: Optional[str],
    tactics: List[str],
    platforms: List[str],
    data_sources: List[str],
    detection: str,
    description: str,
    keywords: List[str],
    log_indicators: List[str],
):
    safe_name = _sanitize_filename(name)
    filename = f"{technique_id}_{safe_name}.md"
    path = os.path.join(out_dir, filename)

    header_lines = [
        f"# {name} ({technique_id})",
        "",
        f"Technique ID: {technique_id}",
        f"Technique Name: {name}",
        f"Tactic(s): {', '.join(tactics) if tactics else 'Unknown'}",
        f"Platforms: {', '.join(platforms) if platforms else 'Unknown'}",
        f"Type: {'Sub-technique' if is_sub else 'Technique'}",
    ]
    if is_sub and INCLUDE_PARENT_FOR_SUBTECHNIQUES and parent_ext_id:
        header_lines.append(f"Parent: {parent_ext_id}")
    if url:
        header_lines.append(f"Reference: {url}")

    header_lines += [
        "",
        "Keywords:",
        ", ".join(keywords) if keywords else "",
        "",
        "Log Indicators:",
        "\n".join(f"- {x}" for x in log_indicators) if log_indicators else "- (none)",
        "",
        "---",
        "",
        "## Description",
        _wrap_md(description) if description else "No description available in source JSON.",
        "",
        "## Detection",
        _wrap_md(detection) if detection else "No detection guidance available in source JSON.",
        "",
        "## Data Sources",
        ", ".join(data_sources) if data_sources else "Unknown",
        "",
        "## Notes",
        "This file was generated from enterprise-attack.json for RAG retrieval in Open WebUI.",
        "",
    ]

    os.makedirs(out_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header_lines))


# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="Convert enterprise-attack.json into RAG-friendly ATT&CK technique MD files.")
    ap.add_argument("--input", default=DEFAULT_INPUT, help="Path to enterprise-attack.json")
    ap.add_argument("--output", default=DEFAULT_OUTPUT, help="Output directory for .md files")
    args = ap.parse_args()

    in_path = args.input
    out_dir = args.output

    if not os.path.isfile(in_path):
        raise FileNotFoundError(f"Input JSON not found: {in_path}")

    with open(in_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("Unexpected file format: missing bundle['objects'] list.")

    # Map STIX IDs -> attack-pattern objects
    attack_patterns: Dict[str, Dict[str, Any]] = {}
    for o in objects:
        if o.get("type") == "attack-pattern" and o.get("id"):
            attack_patterns[str(o["id"])] = o

    sub_to_parent = _build_subtechnique_parent_map(objects)

    written = 0
    skipped = 0

    for stix_id, obj in attack_patterns.items():
        technique_id, url = _get_external_id_and_url(obj)
        if not technique_id:
            skipped += 1
            continue

        name = _norm_space(obj.get("name", "")) or technique_id
        is_sub = bool(obj.get("x_mitre_is_subtechnique", False))

        tactics = _extract_kill_chain_tactics(obj)
        platforms = _extract_list(obj, "x_mitre_platforms")
        data_sources = _extract_list(obj, "x_mitre_data_sources")
        aliases = _extract_list(obj, "x_mitre_aliases")

        detection = obj.get("x_mitre_detection") or ""
        description = obj.get("description") or ""

        parent_ext_id = None
        if is_sub and INCLUDE_PARENT_FOR_SUBTECHNIQUES:
            parent_stix = sub_to_parent.get(stix_id)
            if parent_stix and parent_stix in attack_patterns:
                parent_obj = attack_patterns[parent_stix]
                parent_ext_id, _ = _get_external_id_and_url(parent_obj)

        keywords = _compose_keywords(
            technique_id=technique_id,
            name=name,
            tactics=tactics,
            platforms=platforms,
            data_sources=data_sources,
            aliases=aliases,
            description=description,
            detection=detection,
        )

        log_indicators = _compose_log_indicators(
            name=name,
            platforms=platforms,
            keywords=keywords,
        )

        _write_md_file(
            out_dir=out_dir,
            technique_id=technique_id,
            name=name,
            url=url,
            is_sub=is_sub,
            parent_ext_id=parent_ext_id,
            tactics=tactics,
            platforms=platforms,
            data_sources=data_sources,
            detection=detection,
            description=description,
            keywords=keywords,
            log_indicators=log_indicators,
        )
        written += 1

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] Done.")
    print(f"Input:  {in_path}")
    print(f"Output: {out_dir}")
    print(f"Written technique files: {written}")
    print(f"Skipped (no external_id): {skipped}")
    print("")
    print("Next steps:")
    print("1) In Open WebUI: create a Knowledge Base (e.g., 'ATT&CK Enterprise Techniques').")
    print("2) Upload the entire output folder of .md files.")
    print("3) In your prompt/system prompt, have the model extract verbatim indicators and call query_knowledge_files(count=12).")


if __name__ == "__main__":
    main()

