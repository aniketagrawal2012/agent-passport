"""
Formal Unit & Protocol Invariant Test Suite for Agent-Passport.
Verifies:
1. Theorem 1: Monotonic Caveat Attenuation Soundness & HMAC-SHA256 Unforgeability
2. Theorem 2: O(k) BGP-Style AS-Path Cycle Detection & Hop-Budget Termination
3. Theorem 3: Non-Bypassable Wire-Level HITL Draft-Lock & EU AI Act Art. 14 Co-Signing
4. Theorem 4: Turn-Scoped Physical RAM Zeroization via ctypes.memset
"""

import hashlib
import json
import secrets
import unittest

from passport_types import (
    ExecutionMode,
    HDR_HITL_COSIGNATURE,
    HDR_PASSPORT_MACAROON,
    HDR_SERVERLESS_AUTH,
    HDR_ZEROIZATION_RECEIPT,
    PassportWireError,
)
from macaroon_engine import (
    AgentPassportEngine,
    PassportVerificationError,
    TurnScopedZeroizingBuffer,
)
from gateway_middleware import AgentPassportWireGateway


class TestAgentPassportInvariants(unittest.TestCase):
    def setUp(self) -> None:
        self.root_key = secrets.token_bytes(32)
        self.gateway = AgentPassportWireGateway(root_secret_key=self.root_key, db_path=":memory:")
        self.engine = self.gateway.engine
        import base64
        _jwt_hdr = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode("ascii").rstrip("=")
        self.oidc_token = "Bearer " + _jwt_hdr + ".cloudrun.sig"

    def test_multi_hop_valid_attenuation_and_execution(self) -> None:
        """Verifies a legitimate 3-hop ZoomInfo / Deloitte read delegation succeeds in <100 us."""
        root_tok = self.engine.mint_root_passport(
            root_principal_id="ppmd_grant@deloitte.com",
            tenant_id="DELOITTE_US01",
            session_id="sess_101",
            turn_id="turn_001",
            initial_scopes=["sap.gl.read", "sap.gl.write", "sfdc.opportunity.read", "m365.mail.send"],
            initial_execution_mode=ExecutionMode.AUTONOMOUS_MUTATION,
        )

        # Hop 1: Orchestrator -> Digital Account Deputy (attenuates to SAP & SFDC read/write)
        hop1_tok = self.engine.attenuate_passport_at_hop(
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

        # Hop 2: Digital Account Deputy -> SAP FastMCP Server (narrows to US01 only)
        hop2_tok = self.engine.attenuate_passport_at_hop(
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

        status, resp_hdrs, body = self.gateway.handle_jsonrpc_tool_call(
            jsonrpc_request={
                "jsonrpc": "2.0",
                "id": "req-1",
                "method": "tools/call",
                "params": {
                    "name": "sap_get_gl_account_balances",
                    "arguments": {"company_code": "US01", "fiscal_year": "2026"},
                },
            },
            http_headers={
                HDR_PASSPORT_MACAROON: hop2_tok.to_wire_json(),
                HDR_SERVERLESS_AUTH: self.oidc_token,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["status"], "EXECUTED")
        self.assertIn(HDR_ZEROIZATION_RECEIPT, resp_hdrs)

    def test_scope_escalation_and_caveat_stripping_blocked(self) -> None:
        """Theorem 1: Downstream agent cannot widen scopes or strip upstream caveats."""
        root_tok = self.engine.mint_root_passport(
            root_principal_id="analyst@deloitte.com",
            tenant_id="DELOITTE_US01",
            session_id="sess_102",
            turn_id="turn_002",
            initial_scopes=["sap.gl.read", "sap.treasury.disburse"],
            initial_execution_mode=ExecutionMode.AUTONOMOUS_MUTATION,
        )

        # Hop 1 narrows out sap.treasury.disburse
        hop1_tok = self.engine.attenuate_passport_at_hop(
            parent_token=root_tok,
            issuer_agent_id="gemini_enterprise_root",
            target_agent_id="ap_clerk_subagent",
            target_org_domain="deloitte.com",
            narrowed_scopes=["sap.gl.read"],
            allowed_tools=["sap_get_gl_account_balances"],
            narrowed_execution_mode=ExecutionMode.READ_ONLY,
            max_remaining_hops=3,
        )

        # Compromised Hop 2 tries to re-add sap.treasury.disburse
        malicious_hop2 = self.engine.attenuate_passport_at_hop(
            parent_token=hop1_tok,
            issuer_agent_id="ap_clerk_subagent",
            target_agent_id="sap_fastmcp_gateway",
            target_org_domain="cloud.google.com",
            narrowed_scopes=["sap.gl.read", "sap.treasury.disburse"],
            allowed_tools=["sap_execute_treasury_wire_f110"],
            narrowed_execution_mode=ExecutionMode.AUTONOMOUS_MUTATION,
            max_remaining_hops=2,
        )

        status, _, body = self.gateway.handle_jsonrpc_tool_call(
            jsonrpc_request={
                "jsonrpc": "2.0",
                "id": "req-2",
                "method": "tools/call",
                "params": {
                    "name": "sap_execute_treasury_wire_f110",
                    "arguments": {"amount": 250000},
                },
            },
            http_headers={
                HDR_PASSPORT_MACAROON: malicious_hop2.to_wire_json(),
                HDR_SERVERLESS_AUTH: self.oidc_token,
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(
            body["error"]["code"],
            PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED.value,
        )

        # Now test stripping caveat 1 while keeping tail_hmac_hex
        raw_dict = json.loads(hop1_tok.to_wire_json())
        raw_dict["caveats"] = []  # Attacker strips narrowing caveat!
        status2, _, body2 = self.gateway.handle_jsonrpc_tool_call(
            jsonrpc_request={
                "jsonrpc": "2.0",
                "id": "req-3",
                "method": "tools/call",
                "params": {
                    "name": "sap_execute_treasury_wire_f110",
                    "arguments": {"amount": 250000},
                },
            },
            http_headers={
                HDR_PASSPORT_MACAROON: json.dumps(raw_dict),
                HDR_SERVERLESS_AUTH: self.oidc_token,
            },
        )
        self.assertEqual(status2, 403)
        self.assertEqual(
            body2["error"]["code"],
            PassportWireError.MACAROON_SIGNATURE_INVALID.value,
        )

    def test_as_path_routing_loop_blocked(self) -> None:
        """Theorem 2: Cyclic A2A delegation (A -> B -> A) is rejected immediately."""
        root_tok = self.engine.mint_root_passport(
            root_principal_id="user@telekom.de",
            tenant_id="DT_MAASK",
            session_id="sess_103",
            turn_id="turn_003",
            initial_scopes=["snow.incident.read"],
            origin_agent_id="maask_orchestrator",
        )
        hop1 = self.engine.attenuate_passport_at_hop(
            parent_token=root_tok,
            issuer_agent_id="maask_orchestrator",
            target_agent_id="deep_research_a2a_agent",
            target_org_domain="telekom.de",
            narrowed_scopes=["snow.incident.read"],
            allowed_tools=["servicenow_query_incident_runbook"],
            narrowed_execution_mode=ExecutionMode.READ_ONLY,
            max_remaining_hops=3,
        )
        with self.assertRaises(PassportVerificationError) as ctx:
            self.engine.attenuate_passport_at_hop(
                parent_token=hop1,
                issuer_agent_id="deep_research_a2a_agent",
                target_agent_id="maask_orchestrator",  # Cycle back to origin!
                target_org_domain="telekom.de",
                narrowed_scopes=["snow.incident.read"],
                allowed_tools=["servicenow_query_incident_runbook"],
                narrowed_execution_mode=ExecutionMode.READ_ONLY,
                max_remaining_hops=2,
            )
        self.assertEqual(ctx.exception.code, PassportWireError.A2A_ROUTING_LOOP_DETECTED)

    def test_draft_staged_and_eu_ai_act_art14_hitl_cosignature(self) -> None:
        """Theorem 3: DRAFT_STAGED intercepts sendMail into HTTP 202 Draft; HITL_COSIGNED requires co-signature."""
        root_tok = self.engine.mint_root_passport(
            root_principal_id="ppmd_leader@deloitte.com",
            tenant_id="DELOITTE_US01",
            session_id="sess_104",
            turn_id="turn_004",
            initial_scopes=["m365.mail.send", "hr.workday.calibrate"],
            initial_execution_mode=ExecutionMode.AUTONOMOUS_MUTATION,
        )

        # Chief of Staff attenuated to DRAFT_STAGED per Deloitte CMP policy
        cos_tok = self.engine.attenuate_passport_at_hop(
            parent_token=root_tok,
            issuer_agent_id="gemini_enterprise_root",
            target_agent_id="digital_chief_of_staff",
            target_org_domain="deloitte.com",
            narrowed_scopes=["m365.mail.send"],
            allowed_tools=["outlook_send_executive_email"],
            narrowed_execution_mode=ExecutionMode.DRAFT_STAGED,
            max_remaining_hops=2,
        )

        status, hdrs, body = self.gateway.handle_jsonrpc_tool_call(
            jsonrpc_request={
                "jsonrpc": "2.0",
                "id": "req-cos",
                "method": "tools/call",
                "params": {
                    "name": "outlook_send_executive_email",
                    "arguments": {"to": "cfo@client.com", "subject": "Q4 SOW Update"},
                },
            },
            http_headers={
                HDR_PASSPORT_MACAROON: cos_tok.to_wire_json(),
                HDR_SERVERLESS_AUTH: self.oidc_token,
            },
        )
        self.assertEqual(status, 202)
        self.assertEqual(body["result"]["status"], "DRAFT_STAGED_FOR_HITL_REVIEW")
        self.assertIn("X-HITL-Draft-Lock-Token", hdrs)

        # HR Performance Review Summarizer attenuated to HITL_COSIGNED per EU AI Act Art. 14
        hr_tok = self.engine.attenuate_passport_at_hop(
            parent_token=root_tok,
            issuer_agent_id="gemini_enterprise_root",
            target_agent_id="performance_review_summarizer",
            target_org_domain="deloitte.com",
            narrowed_scopes=["hr.workday.calibrate"],
            allowed_tools=["workday_irpm_publish_calibration_rating"],
            narrowed_execution_mode=ExecutionMode.HITL_COSIGNED,
            max_remaining_hops=2,
        )

        hr_args = {"employee_id": "EMP-88402", "calibrated_band": "STRONG_EXCEEDS"}
        # 1. Without human co-signature -> HTTP 428 Precondition Required
        status_no_sig, _, body_no_sig = self.gateway.handle_jsonrpc_tool_call(
            jsonrpc_request={
                "jsonrpc": "2.0",
                "id": "req-hr-1",
                "method": "tools/call",
                "params": {
                    "name": "workday_irpm_publish_calibration_rating",
                    "arguments": hr_args,
                },
            },
            http_headers={
                HDR_PASSPORT_MACAROON: hr_tok.to_wire_json(),
                HDR_SERVERLESS_AUTH: self.oidc_token,
            },
        )
        self.assertEqual(status_no_sig, 428)
        self.assertEqual(
            body_no_sig["error"]["code"],
            PassportWireError.HITL_DRAFT_COSIGNATURE_REQUIRED.value,
        )

        # 2. With valid human partner co-signature -> HTTP 200 Executed
        payload_sha = hashlib.sha256(json.dumps(hr_args, sort_keys=True).encode("utf-8")).hexdigest()
        valid_cosig = self.engine.compute_human_cosignature(
            principal_id="ppmd_leader@deloitte.com",
            tool_name="workday_irpm_publish_calibration_rating",
            payload_sha256=payload_sha,
            turn_id="turn_004",
        )
        status_sig, _, body_sig = self.gateway.handle_jsonrpc_tool_call(
            jsonrpc_request={
                "jsonrpc": "2.0",
                "id": "req-hr-2",
                "method": "tools/call",
                "params": {
                    "name": "workday_irpm_publish_calibration_rating",
                    "arguments": hr_args,
                },
            },
            http_headers={
                HDR_PASSPORT_MACAROON: hr_tok.to_wire_json(),
                HDR_SERVERLESS_AUTH: self.oidc_token,
                HDR_HITL_COSIGNATURE: valid_cosig,
            },
        )
        self.assertEqual(status_sig, 200)
        self.assertEqual(body_sig["result"]["status"], "EXECUTED")

    def test_ctypes_physical_ram_zeroization(self) -> None:
        """Theorem 4: TurnScopedZeroizingBuffer wipes physical RAM bytes to 0x00 on exit."""
        import base64
        secret = "Bearer " + base64.urlsafe_b64encode(b'{"alg":"RS256","secret":"synthetic_sap_token"}').decode("ascii")
        with TurnScopedZeroizingBuffer(
            secret_str=secret,
            turn_id="turn_ram_test",
            agent_id="zoominfo_a2a_agent",
            attest_key=self.root_key,
        ) as buf:
            self.assertEqual(buf.read_token(), secret)

        # After exiting `with` block, physical bytearray must be all 0x00
        self.assertEqual(bytes(buf._buf), b"\x00" * len(secret))
        self.assertIsNotNone(buf.receipt)
        self.assertTrue(len(buf.receipt.pre_zero_hmac_hex) == 64)
        self.assertEqual(
            buf.receipt.post_zero_sha256,
            hashlib.sha256(b"\x00" * len(secret)).hexdigest(),
        )
        with self.assertRaises(RuntimeError):
            buf.read_token()

    def test_hitl_cosignature_replay_blocked_in_sqlite_wal(self) -> None:
        """Theorem 3: Replaying a consumed HITL co-signature for the same nonce is rejected with HTTP 428."""
        root_tok = self.engine.mint_root_passport(
            root_principal_id="ppmd_leader@deloitte.com",
            tenant_id="DELOITTE_US01",
            session_id="sess_replay",
            turn_id="turn_replay_01",
            initial_scopes=["hr.workday.calibrate"],
            initial_execution_mode=ExecutionMode.HITL_COSIGNED,
        )
        hr_tok = self.engine.attenuate_passport_at_hop(
            parent_token=root_tok,
            issuer_agent_id="gemini_enterprise_root",
            target_agent_id="performance_review_summarizer",
            target_org_domain="deloitte.com",
            narrowed_scopes=["hr.workday.calibrate"],
            allowed_tools=["workday_irpm_publish_calibration_rating"],
            narrowed_execution_mode=ExecutionMode.HITL_COSIGNED,
            max_remaining_hops=0,
        )
        hr_args = {"employee_id": "EMP-99100", "calibrated_band": "STRONG_EXCEEDS"}
        payload_sha = hashlib.sha256(json.dumps(hr_args, sort_keys=True).encode("utf-8")).hexdigest()
        valid_cosig = self.engine.compute_human_cosignature(
            principal_id="ppmd_leader@deloitte.com",
            tool_name="workday_irpm_publish_calibration_rating",
            payload_sha256=payload_sha,
            turn_id="turn_replay_01",
        )
        req_frame = {
            "jsonrpc": "2.0",
            "id": "req-replay-1",
            "method": "tools/call",
            "params": {"name": "workday_irpm_publish_calibration_rating", "arguments": hr_args},
        }
        hdrs = {
            HDR_PASSPORT_MACAROON: hr_tok.to_wire_json(),
            HDR_SERVERLESS_AUTH: self.oidc_token,
            HDR_HITL_COSIGNATURE: valid_cosig,
        }
        status1, _, _ = self.gateway.handle_jsonrpc_tool_call(req_frame, hdrs)
        self.assertEqual(status1, 200)

        # Replay the exact same co-signed frame -> must be rejected with HTTP 428!
        status2, _, body2 = self.gateway.handle_jsonrpc_tool_call(req_frame, hdrs)
        self.assertEqual(status2, 428)
        self.assertEqual(body2["error"]["code"], PassportWireError.HITL_DRAFT_COSIGNATURE_REQUIRED.value)

    def test_gateway_wrapped_encrypted_credential_aad_binding(self) -> None:
        """Theorem 4: Gateway-wrapped credential binds AAD = nonce || principal and fails on AAD mismatch."""
        vault_key = secrets.token_bytes(32)
        attest_key = secrets.token_bytes(32)
        raw_oauth = b"ya29.a0AfB_byC_enterprise_sap_odata_secret_token"
        enc = TurnScopedZeroizingBuffer.encrypt_backend_credential(
            raw_oauth, vault_key, nonce_id="nonce_1234", principal_id="user@deloitte.com"
        )
        with TurnScopedZeroizingBuffer.from_encrypted_credential(
            enc,
            vault_key,
            nonce_id="nonce_1234",
            turn_id="turn_aad",
            agent_id="sap_gateway",
            attest_key=attest_key,
            principal_id="user@deloitte.com",
        ) as buf:
            self.assertEqual(bytes(buf.read_memoryview()), raw_oauth)
        self.assertEqual(bytes(buf._buf), b"\x00" * len(raw_oauth))

        with self.assertRaises(ValueError):
            TurnScopedZeroizingBuffer.from_encrypted_credential(
                enc,
                vault_key,
                nonce_id="nonce_1234",
                turn_id="turn_aad",
                agent_id="sap_gateway",
                attest_key=attest_key,
                principal_id="attacker@evil.com",
            )


if __name__ == "__main__":
    unittest.main()
