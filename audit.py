#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml
from packaging.version import Version 

# --- Import Rules and Data Structures from rules.py ---
from rules import (
    Finding, 
    SEVERITY_LEVELS, 
    scan_workflow, 
    safe_yaml_loads, 
) 

# AI advisor: Import 'advise' function from the external advise.py file
try:
    from advise import advise
except Exception:
    def advise(*args, **kwargs):
        # Fallback to prevent crashes if the file/deps are missing
        print("::warning title=AI Advisor::Could not import 'advise'. AI functionality will be skipped.")
        return []

GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com")

# ---------- Inputs ----------
TOKEN = os.environ.get("INPUT_GITHUB_TOKEN", "")
ORG = os.environ.get("INPUT_ORG", "").strip()
REPO_INPUT = os.environ.get("INPUT_REPO", "").strip()
INCLUDE_ARCHIVED = os.environ.get("INPUT_INCLUDE_ARCHIVED", "false").lower() == "true"
EXCLUDE_PATTERNS = [p.strip() for p in os.environ.get("INPUT_EXCLUDE", "").split(",") if p.strip()]
FAIL_ON_FINDINGS = os.environ.get("INPUT_FAIL_ON_FINDINGS", "false").lower() == "true"
OUTPUT_FORMAT = os.environ.get("INPUT_OUTPUT_FORMAT", "both").lower()
DEFAULT_REPO = os.environ.get("GITHUB_REPOSITORY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
AI_ENABLED = os.environ.get("INPUT_AI_ENABLED", "false").lower() == "true"
MIN_SEVERITY_INPUT = os.environ.get("INPUT_MIN_SEVERITY", "low").lower().strip() # NEW INPUT


# ---------- Helpers (Kept as they support I/O/Flow) ----------
def gh_headers() -> Dict[str, str]:
    return {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}

def match_any(path: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in patterns)

def list_org_repos(org: str) -> List[Dict[str, Any]]:
    out = []
    url = f"{GITHUB_API}/orgs/{org}/repos"
    params = {"per_page": 100, "type": "all"}
    
    # Simpler request block, relying on main() to analyze the result count
    while True:
        r = requests.get(url, headers=gh_headers(), params=params)
        r.raise_for_status() # Let this raise for general connection/auth errors
        batch = r.json()
        for repo in batch:
            if not INCLUDE_ARCHIVED and repo.get("archived"):
                continue
            out.append(repo)
        if "next" in r.links:
            url = r.links["next"]["url"]
            params = {}
        else:
            break
    return out

def list_repo_workflows(owner: str, repo: str) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    contents_url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/.github/workflows"
    r = requests.get(contents_url, headers=gh_headers())
    if r.status_code == 404:
        return results
    r.raise_for_status()
    for item in r.json():
        if item.get("type") != "file":
            continue
        name = item.get("name", "")
        if not (name.endswith(".yml") or name.endswith(".yaml")):
            continue
        if match_any(item.get("path", name), EXCLUDE_PATTERNS):
            continue
        file_r = requests.get(item["download_url"], headers=gh_headers())
        file_r.raise_for_status()
        results.append((item.get("path", name), file_r.text))
    return results

def list_local_workflows() -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    root = ".github/workflows"
    if not os.path.isdir(root):
        return results
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if not (fn.endswith(".yml") or fn.endswith(".yaml")):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, ".")
            if match_any(rel, EXCLUDE_PATTERNS):
                continue
            with open(path, "r", encoding="utf-8") as f:
                results.append((rel.replace("\\", "/"), f.read()))
    return results


# ---------- Reporting (Uses imported Finding and SEVERITY_LEVELS) ----------
def severity_icon(sev: str) -> str:
    if sev == "high":
        return "🔴 **High**"
    if sev == "medium":
        return "🟠 Medium"
    return "🟢 Low"

def severity_log(sev: str) -> str:
    if sev == "high":
        return "\033[91m🔴 High\033[0m"
    if sev == "medium":
        return "\033[93m🟠 Medium\033[0m"
    return "\033[92m🟢 Low\033[0m"

def write_summary(findings: List[Finding]) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY", "workflow-summary.md")
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    # Sorting key uses the SEVERITY_LEVELS defined earlier
    ordered = sorted(findings, key=lambda f: SEVERITY_LEVELS.get(f.severity.lower(), 99))

    # Determine scope for summary: ORG if set, else repo name
    if ORG:
        scope = ORG
    elif REPO_INPUT:
        scope = REPO_INPUT
    else:
        scope = DEFAULT_REPO or "(local)"

    lines = [
        "# 🛡️ Workflow Audit Report",
        "",
        f"**Total issues detected: {len(findings)}** (Minimum severity: {MIN_SEVERITY_INPUT.capitalize()})",
        f"Scope: {scope}",
        "",
        f"- 🔴 High: {counts['high']}",
        f"- 🟠 Medium: {counts['medium']}",
        f"- 🟢 Low: {counts['low']}",
        "",
        "| Severity | Rule | Repo | File | Job | Step | Message |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in ordered:
        lines.append(
            f"| {severity_icon(f.severity)} | {f.rule_id} | {f.repo} | {f.file} | {f.job or ''} | {f.step or ''} | {f.message} |"
        )
    with open(summary_file, "a", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")


def print_log_table(findings: List[Finding]) -> None:
    if not findings:
        print("✅ No issues found")
        return

    ordered = sorted(findings, key=lambda f: SEVERITY_LEVELS.get(f.severity.lower(), 99))

    print("\n=== 🛡️ Workflow Audit Findings ===")
    print(f"{'Severity':<15} {'Rule':<20} {'Repo':<25} {'File':<30} {'Job':<20} {'Step':<20} Message")
    print("-" * 130)
    for f in ordered:
        print(
            f"{severity_log(f.severity):<15} {f.rule_id:<20} {f.repo:<25} {f.file:<30} {str(f.job or ''):<20} {str(f.step or ''):<20} {f.message}"
        )
    print("-" * 130)

def write_sarif(findings: List[Finding]) -> None:
    rules = {}
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "fullDescription": {"text": f.rule_id},
            }
    results = []
    for f in findings:
        level = {"high": "error", "medium": "warning", "low": "note"}[f.severity]
        results.append({
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {"repo": f.repo, "job": f.job or "", "step": f.step or ""},
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "workflow-auditor", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    with open("workflow-audit.sarif", "w", encoding="utf-8") as fp:
        json.dump(sarif, fp, indent=2)

# ---------- Execution (MAIN LOGIC WITH SCOPE CHECK) ----------
def main() -> int:
    if not TOKEN:
        print("::error title=Missing input::INPUT_GITHUB_TOKEN is required")
        return 2

    targets: List[Tuple[str, List[Tuple[str, str]]]] = []
    findings: List[Finding] = []
    
    org_scan_attempted = bool(ORG)
    org_repo_count = 0 # Track how many repos the API call actually returned

    # --- ORG/REPO Target Collection ---
    if ORG:
        repos = []
        try:
            # list_org_repos now relies on standard HTTP errors for connection issues
            repos = list_org_repos(ORG)
            org_repo_count = len(repos)

        except requests.HTTPError as e:
            # Catch API errors (like rate limiting, etc.)
            print(f"::notice title=Org Scan Aborted::API error while listing repos for '{ORG}': {e}. Proceeding with collected data.")
            repos = [] 
        
        # Process retrieved repos
        for r in repos:
            full = r["full_name"]
            owner, name = full.split("/")
            try:
                wfs = list_repo_workflows(owner, name)
            except requests.HTTPError as e:
                print(f"::warning title=Skip repo::{full}: {e}")
                continue
            if not wfs:
                continue
            targets.append((full, wfs))

        initial_target_count = len(targets)
        
        # --- NEW LOGIC: FALLBACK & WARNING BASED ON COUNT ---
        if org_scan_attempted and org_repo_count == 0:
            # Case 1: ORG scan was attempted but returned zero repos (likely permission issue or org has no repos)
            if DEFAULT_REPO:
                print(f"::warning title=Org Scope Failed::The GITHUB_TOKEN failed to list any repositories for '{ORG}'. This indicates missing 'read:org' or 'repo' scope. Falling back to the current repository.")
                repo = DEFAULT_REPO or "(local)"
                wfs = list_local_workflows()
                if wfs:
                    targets.append((repo, wfs))
            else:
                 print(f"::warning title=Org Scope Failed::The GITHUB_TOKEN failed to list any repositories for '{ORG}'. This indicates missing 'read:org' or 'repo' scope. No targets to scan.")

        elif org_scan_attempted and org_repo_count == 1:
             # Case 2: ORG scan returned exactly one repo. This repo is almost certainly the self-repo.
             # We assume the org scope failed and only the default repo was visible/scanned.
             if initial_target_count == 1 and targets[0][0] == DEFAULT_REPO:
                 print(f"::warning title=Org Scope Failed::The GITHUB_TOKEN likely lacks organization access ('read:org' scope). Audit scope limited to the current repository: {DEFAULT_REPO}.")
             # If targets[0][0] != DEFAULT_REPO, it means the org genuinely only has one repo, and it's not the one running the action, so we continue.


    elif REPO_INPUT:
        owner, name = REPO_INPUT.split("/")
        wfs = list_repo_workflows(owner, name)
        targets.append((REPO_INPUT, wfs))
    else:
        repo = DEFAULT_REPO or "(local)"
        wfs = list_local_workflows()
        targets.append((repo, wfs))

    # ---- AI Setup and Logging Pre-checks ----
    is_ai_ready = AI_ENABLED and OPENROUTER_API_KEY
    if not AI_ENABLED:
        print("::notice title=AI Advisor::Skipped (AI disabled)")
    elif not OPENROUTER_API_KEY:
        print("::warning title=AI Advisor::Skipped (OPENROUTER_API_KEY missing)")

    ai_findings_count = 0 

    # --- MAIN LOOP (Static Analysis + AI Call) ---
    for repo, wf_files in targets:
        for path, content in wf_files:
            # SYNTAX FIX: This line was causing the crash
            if match_any(path, EXCLUDE_PATTERNS):
                continue
            
            # 1. Static Analysis Pass - **CALLS IMPORTED FUNCTION**
            rule_fs = scan_workflow(repo, path, content)
            findings.extend(rule_fs)

            # 2. AI Advisor Pass (Only if ready)
            if is_ai_ready:
                try:
                    # Print to standard log, NOT as an annotation
                    print(f"Notice: Starting OpenRouter analysis for {path}") 
                    
                    ai_fs = advise(repo, path, content, [asdict(f) for f in rule_fs])
                    
                    if ai_fs:
                        ai_findings_count += len(ai_fs)
                        for af in ai_fs:
                            findings.append(Finding(
                                rule_id=af['rule_id'], 
                                severity=af["severity"],
                                message=f"(AI) {af['message']}",
                                repo=repo,
                                file=path,
                                job=af.get("job"),
                                step=af.get("step"),
                            ))
                        # Print to standard log for confirmation
                        print(f"Notice: AI analysis for {path} complete. Found {len(ai_fs)} findings.")

                except Exception as e:
                    print(f"::warning title=AI Advisor::Execution failed for {path}: {e}")

    # --- Consolidated AI Summary (AFTER ALL FILES ARE PROCESSED) ---
    if is_ai_ready:
        if ai_findings_count > 0:
            print(f"::notice title=AI Advisor::AI analysis completed and found {ai_findings_count} additional recommendations.")
        else:
            print(f"::notice title=AI Advisor::AI analysis completed, no additional recommendations found.")
    
    # --- FILTERING FINDINGS BASED ON MIN_SEVERITY ---
    min_level = SEVERITY_LEVELS.get(MIN_SEVERITY_INPUT, SEVERITY_LEVELS["low"])
    
    filtered_findings: List[Finding] = []
    
    for f in findings:
        finding_level = SEVERITY_LEVELS.get(f.severity.lower(), -1)
        if finding_level <= min_level:
            filtered_findings.append(f)

    print(f"Notice: Filtering results. Showing findings with severity '{MIN_SEVERITY_INPUT}' ({min_level}) and higher. {len(filtered_findings)} of {len(findings)} total results included.")
    
    # --- REPORTING (Using filtered_findings) ---
    write_summary(filtered_findings)
    print("Notice: GitHub summary written")

    print_log_table(filtered_findings)

    if OUTPUT_FORMAT in ("sarif", "both"):
        write_sarif(filtered_findings)
        print("Notice: workflow-audit.sarif written")

    if FAIL_ON_FINDINGS and filtered_findings:
        print(f"\033[91m❌ Issues found: {len(filtered_findings)}. Failing the run due to fail_on_findings=true in your configuration.\033[0m")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())