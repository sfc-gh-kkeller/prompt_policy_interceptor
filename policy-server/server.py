from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Cortex Proxy Policy Server", version="1.0.0")

POLICY_PATH = Path(__file__).parent.parent / "policies.toml"


class PolicyRule(BaseModel):
    enabled: bool = True
    severity: str = "medium"
    description: str = ""
    examples: list[str] = []


class PolicyConfig(BaseModel):
    enabled: bool = True
    judge_model: str = "claude-4-sonnet"
    action: str = "block"
    max_evaluation_tokens: int = 1024
    source: str = "local"
    server_url: str | None = None
    rules: dict[str, PolicyRule] = {}


class EvaluateRequest(BaseModel):
    prompt: str
    context: dict[str, Any] | None = None


class EvaluateResponse(BaseModel):
    allowed: bool
    violated_rule: str | None = None
    reason: str | None = None
    severity: str | None = None


_config: PolicyConfig | None = None


def load_config() -> PolicyConfig:
    global _config
    if _config is not None:
        return _config
    if not POLICY_PATH.exists():
        raise HTTPException(status_code=500, detail=f"Policy file not found: {POLICY_PATH}")
    with open(POLICY_PATH, "rb") as f:
        raw = tomllib.load(f)
    policy_raw = raw.get("policy", {})
    rules = {}
    for name, rule_data in policy_raw.get("rules", {}).items():
        rules[name] = PolicyRule(**rule_data)
    _config = PolicyConfig(
        enabled=policy_raw.get("enabled", True),
        judge_model=policy_raw.get("judge_model", "claude-4-sonnet"),
        action=policy_raw.get("action", "block"),
        max_evaluation_tokens=policy_raw.get("max_evaluation_tokens", 1024),
        source=policy_raw.get("source", "local"),
        server_url=policy_raw.get("server_url"),
        rules=rules,
    )
    return _config


@app.get("/health")
async def health():
    return {"status": "ok", "service": "policy-server"}


@app.get("/policies")
async def get_policies():
    config = load_config()
    return config.model_dump()


@app.get("/policies/{rule_name}")
async def get_policy_rule(rule_name: str):
    config = load_config()
    if rule_name not in config.rules:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_name}' not found")
    return config.rules[rule_name].model_dump()


@app.put("/policies/{rule_name}")
async def update_policy_rule(rule_name: str, rule: PolicyRule):
    config = load_config()
    config.rules[rule_name] = rule
    return {"status": "updated", "rule": rule_name}


@app.post("/evaluate")
async def evaluate_prompt(req: EvaluateRequest):
    config = load_config()
    if not config.enabled:
        return EvaluateResponse(allowed=True, reason="Policy enforcement disabled")

    prompt_lower = req.prompt.lower()
    for name, rule in config.rules.items():
        if not rule.enabled:
            continue
        for example in rule.examples:
            if example.lower() in prompt_lower:
                return EvaluateResponse(
                    allowed=False,
                    violated_rule=name,
                    reason=f"Prompt matches known pattern: {example}",
                    severity=rule.severity,
                )

    return EvaluateResponse(allowed=True)


@app.post("/reload")
async def reload_config():
    global _config
    _config = None
    load_config()
    return {"status": "reloaded"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8900)
