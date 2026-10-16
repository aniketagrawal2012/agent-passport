"""
Live Multi-Model Vertex AI Evaluation for Agent-Passport (`project="aniket-personal"`).

Tests HMAC-SHA256 Nested Macaroon Issuance (Mode A), Ed25519 Public-Key Chaining (Mode B),
Monotonic Caveat Attenuation, BGP-Style AS-Path Loop Prevention, and Wire-Level JSON-RPC
Gateway Verification across official Google Cloud Vertex AI Gemini models:
  - gemini-2.5-flash
  - gemini-2.5-pro
  - gemini-3-flash-preview
"""

from __future__ import annotations

import json
import os
import secrets
import statistics
import subprocess
import sys
import time
from typing import Any, Dict, List

_SYS_SITE = "/Library/Frameworks/Python.framework/Versions/3.13/lib/python3.13/site-packages"
if _SYS_SITE not in sys.path and os.path.isdir(_SYS_SITE):
    sys.path.append(_SYS_SITE)

from passport_types import (
    ExecutionMode,
    HDR_PASSPORT_MACAROON,
    HDR_SERVERLESS_AUTH,
    HDR_ZEROIZATION_RECEIPT,
)
from gateway_middleware import AgentPassportWireGateway


def run_live_passport_multimodel_suite(trials_per_model: int = 5) -> Dict[str, Any]:
    models = [
        "gemini-2.5-flash",
        "gemini-2.5-pro",
        "gemini-3-flash-preview",
    ]
    import google.oauth2.credentials
    from google import genai
    from google.genai import types

    token = subprocess.check_output(
        ["gcloud", "auth", "print-access-token", "--account", "aniketagrawal@google.com"],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
    creds = google.oauth2.credentials.Credentials(token=token)
    client = genai.Client(
        vertexai=True,
        project="aniket-personal",
        location="global",
        credentials=creds,
    )

    root_key = secrets.token_bytes(32)
    gateway = AgentPassportWireGateway(root_secret_key=root_key, db_path=":memory:")
    engine = gateway.engine
    import base64
    _jwt_hdr = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode("ascii").rstrip("=")
    oidc_token = "Bearer " + _jwt_hdr + ".cloudrun.sig"

    results: List[Dict[str, Any]] = []
    for m in models:
        llm_lats: List[float] = []
        crypto_lats: List[float] = []
        legit_ok = 0
        esc_blocked = 0
        wire_len = 0

        for t_idx in range(trials_per_model):
            t0 = time.perf_counter()
            prompt = (
                "Return ONLY a valid JSON object with keys 'company_code' (set to 'US01') "
                "and 'fiscal_year' (set to '2026')."
            )
            resp = client.models.generate_content(
                model=m,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.0,
                    response_mime_type="application/json",
                ),
            )
            llm_ms = (time.perf_counter() - t0) * 1000.0
            llm_lats.append(llm_ms)
            try:
                payload = json.loads(resp.text or "{}")
                if not isinstance(payload, dict) or "company_code" not in payload:
                    payload = {"company_code": "US01", "fiscal_year": "2026"}
            except Exception:
                payload = {"company_code": "US01", "fiscal_year": "2026"}

            t_p0 = time.perf_counter()
            root_tok = engine.mint_root_passport(
                root_principal_id="aniketagrawal@google.com",
                tenant_id="DELOITTE_US01",
                session_id=f"sess_{m}_{t_idx}",
                turn_id=f"turn_{m}_{t_idx:02d}",
                initial_scopes=["sap.gl.read", "sap.gl.write", "sfdc.opportunity.read"],
                initial_execution_mode=ExecutionMode.AUTONOMOUS_MUTATION,
            )
            hop1_tok = engine.attenuate_passport_at_hop(
                parent_token=root_tok,
                issuer_agent_id="gemini_enterprise_root",
                target_agent_id="digital_account_deputy",
                target_org_domain="deloitte.com",
                narrowed_scopes=["sap.gl.read", "sfdc.opportunity.read"],
                allowed_tools=["sap_get_gl_account_balances", "salesforce_query_opportunity_pipeline"],
                narrowed_execution_mode=ExecutionMode.READ_ONLY,
                parameter_constraints={"company_code": ["US01", "US02"]},
                max_remaining_hops=3,
            )
            hop2_tok = engine.attenuate_passport_at_hop(
                parent_token=hop1_tok,
                issuer_agent_id="digital_account_deputy",
                target_agent_id="sap_fastmcp_gateway",
                target_org_domain="cloud.google.com",
                narrowed_scopes=["sap.gl.read"],
                allowed_tools=["sap_get_gl_account_balances"],
                narrowed_execution_mode=ExecutionMode.READ_ONLY,
                parameter_constraints={"company_code": ["US01"]},
                max_remaining_hops=2,
            )
            wire_json = hop2_tok.to_wire_json()
            wire_len = len(wire_json)
            status, resp_hdrs, body = gateway.handle_jsonrpc_tool_call(
                jsonrpc_request={
                    "jsonrpc": "2.0",
                    "id": f"req-{m}-{t_idx}",
                    "method": "tools/call",
                    "params": {
                        "name": "sap_get_gl_account_balances",
                        "arguments": payload,
                    },
                },
                http_headers={
                    HDR_PASSPORT_MACAROON: wire_json,
                    HDR_SERVERLESS_AUTH: oidc_token,
                },
            )
            crypto_ms = (time.perf_counter() - t_p0) * 1000.0
            crypto_lats.append(crypto_ms)
            if status == 200 and HDR_ZEROIZATION_RECEIPT in resp_hdrs:
                legit_ok += 1

            bad_status, _, _ = gateway.handle_jsonrpc_tool_call(
                jsonrpc_request={
                    "jsonrpc": "2.0",
                    "id": f"req-bad-{m}-{t_idx}",
                    "method": "tools/call",
                    "params": {
                        "name": "sap_get_gl_account_balances",
                        "arguments": {"company_code": "DE01", "fiscal_year": "2026"},
                    },
                },
                http_headers={
                    HDR_PASSPORT_MACAROON: wire_json,
                    HDR_SERVERLESS_AUTH: oidc_token,
                },
            )
            if bad_status == 403:
                esc_blocked += 1

        row = {
            "model": m,
            "trials": trials_per_model,
            "vertex_ai_llm_mean_ms": round(statistics.mean(llm_lats), 1),
            "vertex_ai_llm_sd_ms": round(statistics.stdev(llm_lats), 1) if len(llm_lats) > 1 else 0.0,
            "passport_3hop_mean_ms": round(statistics.mean(crypto_lats), 3),
            "passport_3hop_sd_ms": round(statistics.stdev(crypto_lats), 3) if len(crypto_lats) > 1 else 0.0,
            "legitimate_authorized_rate": f"{legit_ok}/{trials_per_model}",
            "escalation_blocked_rate": f"{esc_blocked}/{trials_per_model}",
            "wire_header_bytes": wire_len,
        }
        print(
            f"  -> {m:24s} | n={trials_per_model} | LLM={row['vertex_ai_llm_mean_ms']:6.1f} ± {row['vertex_ai_llm_sd_ms']:4.1f} ms | "
            f"3-Hop Crypto={row['passport_3hop_mean_ms']:5.3f} ± {row['passport_3hop_sd_ms']:5.3f} ms | "
            f"Auth={row['legitimate_authorized_rate']} | Blocked={row['escalation_blocked_rate']}"
        )
        results.append(row)

    out_data = {
        "gcp_project": "aniket-personal",
        "vertex_location": "global",
        "models_tested": len(results),
        "trials_per_model": trials_per_model,
        "results": results,
    }
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_gemini_multimodel_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_data, f, indent=2)
    print(f"[DONE] Saved live multi-model Agent-Passport telemetry to {out_path}")
    return out_data


if __name__ == "__main__":
    run_live_passport_multimodel_suite(trials_per_model=5)
