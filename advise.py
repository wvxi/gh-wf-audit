# advise.py
# -*- coding: utf-8 -*-
import json
import os
import re
from typing import Any, Dict, List

import requests
from tenacity import retry, stop_after_attempt, wait_exponential
from jsonschema import validate, ValidationError

# Define the expected JSON schema for AI findings
AI_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "medium", "low"]},
                    "message": {"type": "string"},
                    "job": {"type": ["string", "null"]},
                    "step": {"type": ["string", "null"]}
                },
                "required": ["rule_id", "severity", "message"]
            }
        }
    },
    "required": ["findings"]
}

# Hint to guide the model's output (Stricter wording added)
SYSTEM_HINT = (
    "You are a GitHub Actions security and performance reviewer. "
    "Your goal is to identify **additional** risky patterns and modernization opportunities. "
    "Return ONLY compact JSON per the provided schema. No prose. No Markdown. No extra characters before or after the JSON object. The output MUST start with '{' and end with '}'."
)

def _compact_yaml(raw: str, max_chars: int = 8000) -> str:
    """Sanitize and truncate the YAML content for the prompt."""
    raw = re.sub(r"[ \t]+", " ", raw)
    return raw[:max_chars]

def _build_prompt(repo: str, path: str, raw_yaml: str, rule_findings: List[Dict[str, Any]]) -> str:
    """Construct the detailed prompt for the AI model."""
    rules = [{
        "rule_id": f.get("rule_id"),
        "severity": f.get("severity"),
        "message": f.get("message"),
        "job": f.get("job"),
        "step": f.get("step")
    } for f in rule_findings]
    
    return (
        "Goal: identify additional risky patterns and modernization opportunities in a GitHub Actions workflow.\n"
        "Constraints:\n"
        "- Prefer concrete, actionable detections.\n"
        "- Avoid duplicates of provided findings.\n"
        "- If uncertain, skip.\n"
        "- Output JSON with key 'findings' and fields 'rule_id', 'severity', and 'message'.\n\n"
        f"Repo: {repo}\nFile: {path}\n"
        f"ExistingFindingsJSON: {json.dumps(rules)[:4000]}\n\n"
        "WorkflowYAML:\n"
        f"<<<\n{_compact_yaml(raw_yaml)}\n>>>"
    )

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=8))
def _openrouter_call(model: str, token: str, prompt: str, max_new_tokens: int, temperature: float) -> str:
    """Call OpenRouter API with retries and handle communication details."""
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "HTTP-Referer": os.environ.get("GITHUB_SERVER_URL", "https://github.com") + "/" + os.environ.get("GITHUB_REPOSITORY", "workflow-auditor") 
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_HINT},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": max_new_tokens,
        "temperature": temperature
    }

    r = requests.post(url, headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    data = r.json()
    if "choices" in data and data["choices"]:
        return data["choices"][0]["message"]["content"]
    
    return json.dumps(data)

def advise(repo: str, path: str, raw_yaml: str, rule_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run AI advisor pass using OpenRouter and validate results."""
    model = os.environ.get("INPUT_AI_MODEL", "meta-llama/llama-3.1-8b-instruct") # Using meta-llama as it often follows instructions better
    token = os.environ.get("OPENROUTER_API_KEY", "").strip()
    
    if not token:
        # Failsafe check (main script handles the primary skip)
        return []

    max_new = int(os.environ.get("INPUT_AI_MAX_TOKENS", "400"))
    temp = float(os.environ.get("INPUT_AI_TEMPERATURE", "0.1"))

    print(f"🧠 Prompting model {model} for {path}") # Log to standard output, not as annotation
    prompt = _build_prompt(repo, path, raw_yaml, rule_findings)

    try:
        raw = _openrouter_call(model, token, prompt, max_new, temp)
    except Exception as e:
        print(f"❌ AI advisor OpenRouter call failed for {path}: {e}")
        return []

    # --- Response Parsing and Validation (RESILIENT BLOCK) ---
    blob = ""
    try:
        # Step 1: Aggressively extract the JSON object based on braces
        start_index = raw.index('{')
        end_index = raw.rindex('}') + 1
        blob = raw[start_index:end_index]
        
        # Step 2: Clean common LLM errors (e.g., trailing commas, which cause Expecting ',' delimiter)
        blob = re.sub(r',\s*\}', '}', blob)
        blob = re.sub(r',\s*\]', ']', blob)
        
        obj = json.loads(blob)
        
        # Step 3: Validate against the schema
        validate(instance=obj, schema=AI_SCHEMA)
        
    except ValueError: # Catches index/brace errors
        print(f"⚠️ AI response failed to find valid JSON structure for {path}. Raw content starts: {raw[:100]}...")
        return []
    except (json.JSONDecodeError, ValidationError) as e:
        # If validation fails, print the error and the problematic blob
        print(f"⚠️ AI response invalid or not JSON for {path}. Error: {e}")
        print(f"Failed JSON blob starts: {blob[:200]}...")
        return []

    out: List[Dict[str, Any]] = []
    seen = set()
    
    for f in obj.get("findings", []):
        
        # Step 4: Robustly extract/map findings, handling non-compliant model output (e.g., missing rule_id)
        # Attempt to map model's bad fields (like 'type', 'description') to required fields
        rid = str(f.get("rule_id", f.get("type", "") or "")).strip().upper().replace(" ", "_").replace("-", "_")
        sev = str(f.get("severity", "low")).lower()
        msg = str(f.get("message", f.get("description", "") or "")).strip()
        job = f.get("job")
        step = f.get("step")
        
        # Strict checks after mapping
        if not rid or not msg or sev not in {"high", "medium", "low"}:
            # Log the dropped item to understand why validation failed for a specific finding
            print(f"   (Skipped finding: Missing rule_id/message/severity: {f})") 
            continue
            
        rid = rid.strip("_")               # Clean leading/trailing underscores
        rid = f"AI_{rid}"                  # Tag AI-generated findings
        
        key = (rid, sev, msg, job or "", step or "")
        if key in seen:
            continue
        seen.add(key)
        
        out.append({"rule_id": rid, "severity": sev, "message": msg, "job": job, "step": step})

    return out