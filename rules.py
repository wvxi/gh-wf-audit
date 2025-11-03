import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

# ---------- Data structures (copied from main) ----------
@dataclass
class Finding:
    rule_id: str
    severity: str  # high | medium | low
    message: str
    repo: str
    file: str
    job: Optional[str] = None
    step: Optional[str] = None

# Define severity order for filtering (copied from main)
SEVERITY_LEVELS = {
    "high": 0,
    "medium": 1,
    "low": 2
}

# Recommended majors (copied from main)
RECOMMENDED_MAJORS = {
    "actions/checkout": 4,
    "actions/setup-node": 4,
    "actions/setup-python": 5,
    "actions/cache": 4,
    "actions/upload-artifact": 4,
    "actions/download-artifact": 4,
    "github/codeql-action/init": 3,
    "github/codeql-action/analyze": 3,
    "github/codeql-action/upload-sarif": 3,
}

# ---------- Helper functions (required by checks, copied from main) ----------
def is_sha_ref(ref: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))

def parse_uses(value: str) -> Tuple[str, Optional[str]]:
    if value.startswith("docker://"):
        return value, None
    if "@" not in value:
        return value, None
    name, ref = value.split("@", 1)
    return name.strip(), ref.strip()

def get_major(ref: str) -> Optional[int]:
    m = re.match(r"^v?(\d+)(?:[.\-].*)?$", ref)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None

# Placeholder for safe_yaml_loads, which should be passed in or imported
# Since the original used a helper for YAML, we need to assume it's imported
# or defined elsewhere, but for this file, we'll assume the main script
# passes the content already loaded. For full functionality, safe_yaml_loads
# should be imported or passed, but we'll include a minimal definition
# to satisfy `scan_workflow` for now, assuming the content comes in pre-parsed.

# Since scan_workflow uses a utility for YAML loading, let's include it
# here for self-containment, but note the original used `yaml.safe_load_all`.
# We'll need the `yaml` import.
import yaml
def safe_yaml_loads(s: str) -> List[Dict[str, Any]]:
    docs = []
    try:
        for doc in yaml.safe_load_all(s):
            if isinstance(doc, dict):
                docs.append(doc)
    except yaml.YAMLError:
        pass
    return docs

# ---------- Checks (moved from main) ----------
def check_unpinned_actions(repo, file, job, step_name, uses) -> Optional[Finding]:
    name, ref = parse_uses(uses)
    if name.startswith("docker://"):
        if "@" not in name or "sha256:" not in name:
            return Finding("UNPINNED_DOCKER_IMAGE", "low",
                           f"Pin docker image to immutable digest: '{uses}'.",
                           repo, file, job, step_name)
        return None
    if ref is None:
        return Finding("UNPINNED_ACTION", "high",
                       f"Action '{name}' is missing a ref. Pin to a commit SHA or trusted tag.",
                       repo, file, job, step_name)
    if is_sha_ref(ref):
        return None
    return Finding("TAG_PIN_ONLY", "medium",
                   f"Action '{name}@{ref}' is tag-pinned. Prefer a commit SHA.",
                   repo, file, job, step_name)

def check_deprecated_versions(repo, file, job, step_name, uses) -> Optional[Finding]:
    name, ref = parse_uses(uses)
    if name.startswith("docker://") or not ref:
        return None
    base = name.strip()
    parts = base.split("/")
    base_two = "/".join(parts[:2]) if len(parts) >= 2 else base
    rec = RECOMMENDED_MAJORS.get(base) or RECOMMENDED_MAJORS.get(base_two)
    if rec is None:
        return None
    major = get_major(ref) or -1
    if major < rec:
        return Finding("OUTDATED_ACTION", "medium",
                       f"Use '{base_two}@v{rec}' or newer. Found '{uses}'.",
                       repo, file, job, step_name)
    return None

def check_permissions_presence(repo, file, wf) -> Optional[Finding]:
    if "permissions" not in wf:
        return Finding("MISSING_PERMISSIONS", "medium",
                       "Top-level 'permissions' is not set. Use least privilege.",
                       repo, file)
    return None

def check_pull_request_target(repo, file, wf) -> Optional[Finding]:
    events = wf.get("on")
    if events is None:
        return None
    def includes(e):
        if isinstance(events, str): return events == e
        if isinstance(events, list): return e in events
        if isinstance(events, dict): return e in events.keys()
        return False
    if includes("pull_request_target"):
        return Finding("PR_TARGET_EVENT", "high",
                       "Uses 'pull_request_target'. Avoid unless necessary and guarded.",
                       repo, file)
    return None

def check_checkout_persist(repo, file, job, step_name, uses, with_dict) -> Optional[Finding]:
    name, _ = parse_uses(uses)
    if not name.startswith("actions/checkout"):
        return None
    val = with_dict.get("persist-credentials", None) if isinstance(with_dict, dict) else None
    if val is None or str(val).lower() == "true":
        return Finding("CHECKOUT_PERSIST_CREDENTIALS", "medium",
                       "Set 'persist-credentials: false' for forked PRs.",
                       repo, file, job, step_name)
    return None

def check_concurrency(repo, file, wf) -> Optional[Finding]:
    if "concurrency" not in wf:
        return Finding("MISSING_CONCURRENCY", "low",
                       "Add 'concurrency' to cancel duplicate runs and save minutes.",
                       repo, file)
    return None

def check_setup_node_cache(repo, file, job, step_name, uses, with_dict) -> Optional[Finding]:
    name, _ = parse_uses(uses)
    if not name.startswith("actions/setup-node"):
        return None
    cache = (with_dict or {}).get("cache")
    if not cache:
        return Finding("NODE_NO_CACHE", "low",
                       "Use 'with: cache: npm|yarn|pnpm' for faster installs.",
                       repo, file, job, step_name)
    return None

def check_setup_python_cache(repo, file, job, step_name, uses, with_dict) -> Optional[Finding]:
    name, _ = parse_uses(uses)
    if not name.startswith("actions/setup-python"):
        return None
    cache = (with_dict or {}).get("cache")
    if not cache:
        return Finding("PY_NO_CACHE", "low",
                       "Use 'with: cache: pip'.",
                       repo, file, job, step_name)
    return None

def check_fetch_depth(repo, file, job, step_name, uses, with_dict) -> Optional[Finding]:
    name, _ = parse_uses(uses)
    if not name.startswith("actions/checkout"):
        return None
    fd = (with_dict or {}).get("fetch-depth")
    if str(fd).strip() == "0":
        return Finding("FULL_FETCH", "low",
                       "fetch-depth: 0 pulls full history. Use default depth=1 unless required.",
                       repo, file, job, step_name)
    return None

# List of all checks to iterate over (just the ones that take 'uses')
ACTION_CHECKS = (
    check_unpinned_actions,
    check_deprecated_versions,
    check_checkout_persist,
    check_setup_node_cache,
    check_setup_python_cache,
    check_fetch_depth,
)

# List of all checks that take a workflow dict (wf)
WORKFLOW_CHECKS = (
    check_permissions_presence,
    check_pull_request_target,
    check_concurrency,
)

# ---------- Scanner (moved from main) ----------
def scan_workflow(repo: str, file: str, content: str) -> List[Finding]:
    findings: List[Finding] = []
    # Use the local definition of safe_yaml_loads for self-containment
    docs = safe_yaml_loads(content) 
    
    for wf in docs:
        # Check workflow-level rules
        for check in WORKFLOW_CHECKS:
            f = check(repo, file, wf)
            if f: findings.append(f)

        jobs = wf.get("jobs", {})
        if not isinstance(jobs, dict):
            continue
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                step_name = str(step.get("name") or step.get("id") or "unnamed")
                if "uses" in step:
                    uses = str(step["uses"])
                    # Default to empty dict if 'with' is missing or not a dict
                    with_dict = step.get("with", {}) if isinstance(step.get("with"), dict) else {} 
                    
                    for check in ACTION_CHECKS:
                        try:
                            # Determine if the check needs the `with_dict` based on its function signature/name
                            if check in (check_checkout_persist, check_setup_node_cache, check_setup_python_cache, check_fetch_depth):
                                fi = check(repo, file, job_name, step_name, uses, with_dict)
                            else:
                                fi = check(repo, file, job_name, step_name, uses)
                            if fi:
                                findings.append(fi)
                        except Exception:
                            # The original code had a broad exception catch, maintaining that here
                            pass
    return findings