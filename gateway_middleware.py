"""
Agent-Passport: A2A & FastMCP HTTP/JSON-RPC 2.0 Wire Gateway Middleware
and Comparative Baseline Gateways.

Module: gateway_middleware.py
"""

from __future__ import annotations
import hashlib
import hmac
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from passport_types import (
    AgentPassportToken,
    DraftLockReceipt,
    ExecutionMode,
    HDR_AS_PATH_VECTOR,
    HDR_AUTHORIZATION,
    HDR_DRAFT_LOCK_TOKEN,
    HDR_EXECUTION_MODE,
    HDR_HITL_COSIGNATURE,
    HDR_PASSPORT_MACAROON,
    HDR_SERVERLESS_AUTH,
    HDR_ZEROIZATION_RECEIPT,
    PassportWireError,
    ZeroizationReceipt,
    build_agent_card_security_descriptor,
)
from macaroon_engine import (
    AgentPassportEngine,
    PassportVerificationError,
    TurnScopedZeroizingBuffer,
)


class EnterpriseToolCatalog:
    """
    Authentic enterprise tool definitions spanning Deloitte (SAP S/4HANA,
    Outlook Chief of Staff, Workday/Elevant HR Calibration, Salesforce Jupiter),
    ZoomInfo, Teradata, and UKG ServiceNow/Bryte.
    """

    TOOLS: Dict[str, Dict[str, Any]] = {
        "sap_get_gl_account_balances": {
            "required_scope": "sap.gl.read",
            "is_mutating": False,
            "system": "SAP_S4HANA",
        },
        "sap_post_journal_entry_fb01": {
            "required_scope": "sap.gl.write",
            "is_mutating": True,
            "system": "SAP_S4HANA",
        },
        "sap_execute_treasury_wire_f110": {
            "required_scope": "sap.treasury.disburse",
            "is_mutating": True,
            "system": "SAP_S4HANA",
        },
        "sap_flush_sm50_rfc_locks": {
            "required_scope": "sap.basis.sm50.remediate",
            "is_mutating": True,
            "system": "SAP_S4HANA",
        },
        "salesforce_query_opportunity_pipeline": {
            "required_scope": "sfdc.opportunity.read",
            "is_mutating": False,
            "system": "SALESFORCE_JUPITER",
        },
        "salesforce_update_deal_stage": {
            "required_scope": "sfdc.opportunity.write",
            "is_mutating": True,
            "system": "SALESFORCE_JUPITER",
        },
        "outlook_triage_executive_inbox": {
            "required_scope": "m365.mail.read",
            "is_mutating": False,
            "system": "M365_EXCHANGE",
        },
        "outlook_send_executive_email": {
            "required_scope": "m365.mail.send",
            "is_mutating": True,
            "system": "M365_EXCHANGE",
        },
        "workday_irpm_publish_calibration_rating": {
            "required_scope": "hr.workday.calibrate",
            "is_mutating": True,
            "system": "WORKDAY_ELEVANT",
        },
        "servicenow_query_incident_runbook": {
            "required_scope": "snow.incident.read",
            "is_mutating": False,
            "system": "SERVICENOW",
        },
    }


class AgentPassportWireGateway:
    """
    Production A2A & FastMCP Wire Gateway enforcing Agent-Passport protocol headers,
    SQLite WAL linearizable draft/audit persistence, and turn-scoped RAM zeroization.
    """

    def __init__(self, root_secret_key: bytes, db_path: str = ":memory:"):
        self.engine = AgentPassportEngine(root_secret_key=root_secret_key)
        self._attest_key = hashlib.sha256(root_secret_key + b":zeroize").digest()
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS staged_hitl_drafts (
                draft_id TEXT PRIMARY KEY,
                turn_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                execution_mode TEXT NOT NULL,
                lock_hmac_hex TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_hitl_nonces (
                nonce_id TEXT PRIMARY KEY,
                cosig_hex TEXT NOT NULL,
                consumed_at_ns INTEGER NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS passport_wire_audit (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                turn_id TEXT NOT NULL,
                nonce_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                invoked_tool TEXT NOT NULL,
                hop_count INTEGER NOT NULL,
                as_path_json TEXT NOT NULL,
                decision TEXT NOT NULL,
                error_code INTEGER,
                verification_latency_us REAL NOT NULL,
                zeroized_post_sha256 TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )
            """
        )
        self.conn.commit()

    def get_well_known_agent_card(self, agent_id: str, org_domain: str = "cloud.google.com") -> Dict[str, Any]:
        return build_agent_card_security_descriptor(
            agent_id=agent_id,
            org_domain=org_domain,
            supported_modes=[
                ExecutionMode.READ_ONLY,
                ExecutionMode.DRAFT_STAGED,
                ExecutionMode.HITL_COSIGNED,
                ExecutionMode.AUTONOMOUS_MUTATION,
            ],
        )

    def handle_jsonrpc_tool_call(
        self,
        jsonrpc_request: Dict[str, Any],
        http_headers: Dict[str, str],
    ) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
        """
        Processes an inbound A2A `tasks/send` or FastMCP `tools/call` JSON-RPC 2.0
        request frame over HTTP/2, returning:
            (http_status_code, response_headers, jsonrpc_response_body)
        """
        t0_ns = time.perf_counter_ns()
        req_id = jsonrpc_request.get("id", "1")
        params = jsonrpc_request.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        raw_passport_json = http_headers.get(HDR_PASSPORT_MACAROON, "")
        serverless_auth = http_headers.get(HDR_SERVERLESS_AUTH, "")
        hitl_cosig = http_headers.get(HDR_HITL_COSIGNATURE)

        if not raw_passport_json:
            return (
                401,
                {"WWW-Authenticate": 'AgentPassport realm="VertexAI-A2A-MCP"'},
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": PassportWireError.DUAL_HEADER_MISSING.value,
                        "message": f"Missing required {HDR_PASSPORT_MACAROON} wire header",
                    },
                },
            )

        try:
            token = AgentPassportToken.from_wire_json(raw_passport_json)
        except Exception as exc:
            return (
                400,
                {},
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": PassportWireError.MACAROON_SIGNATURE_INVALID.value,
                        "message": f"Malformed passport wire JSON: {exc}",
                    },
                },
            )

        tool_meta = EnterpriseToolCatalog.TOOLS.get(tool_name)
        if not tool_meta:
            return (
                404,
                {},
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool '{tool_name}'"},
                },
            )

        active_agent = token.as_path[-1].asn_agent_id if token.as_path else "gateway"

        # Wrap the sensitive bearer payload in a TurnScopedZeroizingBuffer (try/finally RAM wipe)
        with TurnScopedZeroizingBuffer(
            secret_str=raw_passport_json,
            turn_id=token.turn_id,
            agent_id=active_agent,
            attest_key=self._attest_key,
            nonce_id=token.nonce_id,
        ) as scoped_buf:
            try:
                _ = scoped_buf.read_token()
                allowed, draft_receipt, telemetry = self.engine.verify_passport_and_invocation(
                    token=token,
                    invoked_tool=tool_name,
                    tool_required_scope=tool_meta["required_scope"],
                    is_mutating_tool=tool_meta["is_mutating"],
                    tool_arguments=arguments,
                    serverless_oidc_token=serverless_auth,
                    hitl_cosignature_header=hitl_cosig,
                )
                if tool_meta["is_mutating"] and hitl_cosig and draft_receipt is None:
                    try:
                        self.conn.execute(
                            "INSERT INTO consumed_hitl_nonces (nonce_id, cosig_hex, consumed_at_ns) VALUES (?, ?, ?)",
                            (token.nonce_id, hitl_cosig, time.time_ns()),
                        )
                        self.conn.commit()
                    except sqlite3.IntegrityError:
                        raise PassportVerificationError(
                            PassportWireError.HITL_DRAFT_COSIGNATURE_REQUIRED,
                            f"Replay attack blocked: HITL nonce '{token.nonce_id}' already consumed in SQLite WAL",
                        )
            except PassportVerificationError as verr:
                zero_rcpt = scoped_buf.zeroize()
                lat_us = (time.perf_counter_ns() - t0_ns) / 1000.0
                self._record_audit(
                    turn_id=token.turn_id,
                    nonce_id=token.nonce_id,
                    principal_id=token.root_principal_id,
                    invoked_tool=tool_name,
                    hop_count=len(token.caveats),
                    as_path=[h.asn_agent_id for h in token.as_path],
                    decision="DENIED",
                    error_code=verr.code.value,
                    latency_us=lat_us,
                    zero_sha256=zero_rcpt.post_zero_sha256,
                )
                http_code = 428 if verr.code == PassportWireError.HITL_DRAFT_COSIGNATURE_REQUIRED else 403
                return (
                    http_code,
                    {HDR_ZEROIZATION_RECEIPT: zero_rcpt.to_wire_header()},
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": verr.code.value,
                            "message": verr.message,
                        },
                    },
                )

        # Exiting the `with` block automatically zeroized the buffer via ctypes.memset
        zero_rcpt = scoped_buf.receipt
        assert zero_rcpt is not None

        if draft_receipt is not None:
            # Stage in SQLite WAL table and return HTTP 202 Accepted (Draft Staged)
            self.conn.execute(
                """
                INSERT INTO staged_hitl_drafts (
                    draft_id, turn_id, principal_id, agent_id, tool_name,
                    payload_json, payload_sha256, execution_mode, lock_hmac_hex, status, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    draft_receipt.draft_id,
                    token.turn_id,
                    token.root_principal_id,
                    active_agent,
                    tool_name,
                    json.dumps(arguments, sort_keys=True),
                    draft_receipt.staged_payload_sha256,
                    draft_receipt.execution_mode,
                    draft_receipt.lock_hmac_hex,
                    "STAGED_AWAITING_HITL",
                    draft_receipt.created_at_ns,
                ),
            )
            self.conn.commit()
            self._record_audit(
                turn_id=token.turn_id,
                nonce_id=token.nonce_id,
                principal_id=token.root_principal_id,
                invoked_tool=tool_name,
                hop_count=len(token.caveats),
                as_path=[h.asn_agent_id for h in token.as_path],
                decision="DRAFT_STAGED",
                error_code=None,
                latency_us=telemetry["verification_latency_us"],
                zero_sha256=zero_rcpt.post_zero_sha256,
            )
            resp_headers = {
                HDR_DRAFT_LOCK_TOKEN: draft_receipt.to_wire_header(),
                HDR_ZEROIZATION_RECEIPT: zero_rcpt.to_wire_header(),
                HDR_EXECUTION_MODE: ExecutionMode.DRAFT_STAGED.value,
            }
            return (
                202,
                resp_headers,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "status": "DRAFT_STAGED_FOR_HITL_REVIEW",
                        "draft_id": draft_receipt.draft_id,
                        "tool_name": tool_name,
                        "staged_payload_sha256": draft_receipt.staged_payload_sha256,
                        "telemetry": telemetry,
                    },
                },
            )

        self._record_audit(
            turn_id=token.turn_id,
            nonce_id=token.nonce_id,
            principal_id=token.root_principal_id,
            invoked_tool=tool_name,
            hop_count=len(token.caveats),
            as_path=[h.asn_agent_id for h in token.as_path],
            decision="EXECUTED",
            error_code=None,
            latency_us=telemetry["verification_latency_us"],
            zero_sha256=zero_rcpt.post_zero_sha256,
        )
        resp_headers = {
            HDR_ZEROIZATION_RECEIPT: zero_rcpt.to_wire_header(),
            HDR_EXECUTION_MODE: telemetry["effective_mode"],
        }
        return (
            200,
            resp_headers,
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "status": "EXECUTED",
                    "tool_name": tool_name,
                    "principal_id": token.root_principal_id,
                    "telemetry": telemetry,
                },
            },
        )

    def _record_audit(
        self,
        turn_id: str,
        nonce_id: str,
        principal_id: str,
        invoked_tool: str,
        hop_count: int,
        as_path: List[str],
        decision: str,
        error_code: Optional[int],
        latency_us: float,
        zero_sha256: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO passport_wire_audit (
                turn_id, nonce_id, principal_id, invoked_tool, hop_count,
                as_path_json, decision, error_code, verification_latency_us,
                zeroized_post_sha256, timestamp_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                turn_id,
                nonce_id,
                principal_id,
                invoked_tool,
                hop_count,
                json.dumps(as_path),
                decision,
                error_code,
                latency_us,
                zero_sha256,
                time.time_ns(),
            ),
        )
        self.conn.commit()
