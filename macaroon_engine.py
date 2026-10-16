"""
Agent-Passport: Cryptographic Chained-HMAC Macaroon Engine,
BGP-Style AS-Path Vector Loop Detector, and ctypes Physical RAM Zeroizer.

Module: macaroon_engine.py
"""

from __future__ import annotations
import ctypes
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from passport_types import (
    AgentPassportToken,
    ASPathHop,
    Caveat,
    DraftLockReceipt,
    ExecutionMode,
    PassportWireError,
    ZeroizationReceipt,
)


class PassportVerificationError(Exception):
    """Raised when an Agent-Passport wire frame fails cryptographic or policy verification."""

    def __init__(self, code: PassportWireError, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class TurnScopedZeroizingBuffer:
    """
    Context-managed memory buffer for turn-scoped bearer tokens in Google ADK / A2A.
    Guarantees that sensitive bearer credentials bridged across async boundaries
    are physically overwritten with 0x00 in RAM via ctypes.memset inside a
    deterministic try/finally block at the end of the turn.
    """

    def __init__(self, secret_str: str | bytes | bytearray, turn_id: str, agent_id: str, attest_key: bytes, nonce_id: str = ""):
        if isinstance(secret_str, (bytes, bytearray)):
            self._buf = bytearray(secret_str)
        else:
            self._buf = bytearray(secret_str.encode("utf-8"))
        self._length = len(self._buf)
        self._turn_id = turn_id
        self._agent_id = agent_id
        self._attest_key = attest_key
        self._nonce_id = nonce_id
        c_char_buf = (ctypes.c_char * self._length).from_buffer(self._buf)
        self._mem_addr = ctypes.addressof(c_char_buf)
        self._pre_zero_tag = hmac.new(self._attest_key, self._buf, hashlib.sha256).hexdigest()
        self._zeroized = False
        self.receipt: Optional[ZeroizationReceipt] = None

    @staticmethod
    def encrypt_backend_credential(plaintext_token: bytes, vault_key: bytes, nonce_id: str, principal_id: str = "") -> str:
        """
        Encrypts the root OAuth bearer credential under a leaf-gateway vault key K_vault
        bound to associated data AAD = nonce_id || principal_id so intermediate A2A sub-agents
        never observe plaintext.
        """
        aad_bytes = f"{nonce_id}:{principal_id}".encode("utf-8")
        stream_key = hashlib.pbkdf2_hmac("sha256", vault_key, aad_bytes, 1, dklen=len(plaintext_token))
        cipher_bytes = bytes(a ^ b for a, b in zip(plaintext_token, stream_key))
        tag = hmac.new(vault_key, aad_bytes + cipher_bytes, hashlib.sha256).hexdigest()
        return f"{cipher_bytes.hex()}.{tag}"

    @classmethod
    def from_encrypted_credential(
        cls,
        cipher_envelope: str,
        vault_key: bytes,
        nonce_id: str,
        turn_id: str,
        agent_id: str,
        attest_key: bytes,
        principal_id: str = "",
    ) -> "TurnScopedZeroizingBuffer":
        """
        Decrypts a gateway-wrapped credential directly into a mutable bytearray without str allocation.
        Wraps decryption and tag verification in a try/except block that immediately zeroes out the
        target bytearray via ctypes.memset if authentication fails.
        """
        hex_part, tag_part = cipher_envelope.split(".", 1)
        cipher_bytes = bytes.fromhex(hex_part)
        buf = bytearray(len(cipher_bytes))
        try:
            aad_bytes = f"{nonce_id}:{principal_id}".encode("utf-8")
            stream_key = hashlib.pbkdf2_hmac("sha256", vault_key, aad_bytes, 1, dklen=len(cipher_bytes))
            for idx in range(len(cipher_bytes)):
                buf[idx] = cipher_bytes[idx] ^ stream_key[idx]
            expected_tag = hmac.new(vault_key, aad_bytes + cipher_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_tag, tag_part):
                raise ValueError("Invalid gateway-wrapped credential authentication tag")
            return cls(buf, turn_id=turn_id, agent_id=agent_id, attest_key=attest_key, nonce_id=nonce_id)
        except Exception:
            if len(buf) > 0:
                c_char_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
                ctypes.memset(ctypes.addressof(c_char_buf), 0, len(buf))
            raise

    def read_memoryview(self) -> memoryview:
        """Returns a zero-copy memoryview over the mutable bytearray (zero GC heap str allocation)."""
        if self._zeroized:
            raise RuntimeError("TurnScopedZeroizingBuffer: Attempted to read zeroized token memory")
        return memoryview(self._buf)

    def read_token(self) -> str:
        if self._zeroized:
            raise RuntimeError("TurnScopedZeroizingBuffer: Attempted to read zeroized token memory")
        return self._buf.decode("utf-8")

    def zeroize(self) -> ZeroizationReceipt:
        if not self._zeroized and self._length > 0:
            c_char_buf = (ctypes.c_char * self._length).from_buffer(self._buf)
            ctypes.memset(ctypes.addressof(c_char_buf), 0, self._length)
            self._zeroized = True

        # Post-wipe verification read over physical buffer after memset
        post_hash = hashlib.sha256(self._buf).hexdigest()
        expected_zero_hash = hashlib.sha256(b"\x00" * self._length).hexdigest()
        if post_hash != expected_zero_hash:
            raise RuntimeError("Physical memory zeroization verification failed")

        ts_ns = time.time_ns()
        addr_hex = hex(self._mem_addr)
        msg = (
            f"{self._nonce_id}:{self._turn_id}:{self._agent_id}:{addr_hex}:{self._length}:"
            f"{self._pre_zero_tag}:{post_hash}:{ts_ns}"
        ).encode("utf-8")
        sig = hmac.new(self._attest_key, msg, hashlib.sha256).hexdigest()
        self.receipt = ZeroizationReceipt(
            turn_id=self._turn_id,
            agent_id=self._agent_id,
            buffer_address_hex=addr_hex,
            bytes_zeroized=self._length,
            post_zero_sha256=post_hash,
            timestamp_ns=ts_ns,
            attestation_hmac_hex=sig,
            pre_zero_hmac_hex=self._pre_zero_tag,
            nonce_id=self._nonce_id,
        )
        return self.receipt

    def __enter__(self) -> "TurnScopedZeroizingBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.zeroize()


class AgentPassportEngine:
    """
    Core cryptographic engine implementing:
    1. Chained HMAC-SHA256 Contextual Caveat Macaroons (O(1) per-hop attenuation without IdP round-trips)
    2. Monotonic Scope, Tool, Parameter, and ExecutionMode Attenuation Verification
    3. BGP-Style Signed AS-Path Vector Loop Detection (O(k) cycle prevention)
    4. Wire-Level HITL Draft-Lock Receipt Generation & Human Co-Signature Verification
    """

    def __init__(self, root_secret_key: bytes, hitl_cosign_key: Optional[bytes] = None):
        if len(root_secret_key) < 32:
            raise ValueError("Root secret key must be at least 256 bits (32 bytes)")
        self._root_key = root_secret_key
        self._hitl_key = hitl_cosign_key or hashlib.sha256(root_secret_key + b":hitl_art14").digest()

    @staticmethod
    def _compute_genesis_payload(
        nonce_id: str,
        root_principal_id: str,
        tenant_id: str,
        session_id: str,
        turn_id: str,
        initial_scopes: List[str],
        initial_execution_mode: str,
        issued_at_ns: int,
        expires_at_ns: int,
    ) -> bytes:
        genesis = {
            "nonce_id": nonce_id,
            "root_principal_id": root_principal_id,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "turn_id": turn_id,
            "initial_scopes": sorted(initial_scopes),
            "initial_execution_mode": initial_execution_mode,
            "issued_at_ns": issued_at_ns,
            "expires_at_ns": expires_at_ns,
        }
        return json.dumps(genesis, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def mint_root_passport(
        self,
        root_principal_id: str,
        tenant_id: str,
        session_id: str,
        turn_id: str,
        initial_scopes: List[str],
        initial_execution_mode: ExecutionMode = ExecutionMode.AUTONOMOUS_MUTATION,
        origin_agent_id: str = "gemini_enterprise_root",
        origin_org_domain: str = "google.com",
        ttl_seconds: int = 300,
    ) -> AgentPassportToken:
        """
        Mints a root Agent-Passport token at the initial user-to-orchestrator ingress boundary.
        """
        nonce_id = secrets.token_hex(16)
        now_ns = time.time_ns()
        exp_ns = now_ns + int(ttl_seconds * 1_000_000_000)

        genesis_bytes = self._compute_genesis_payload(
            nonce_id=nonce_id,
            root_principal_id=root_principal_id,
            tenant_id=tenant_id,
            session_id=session_id,
            turn_id=turn_id,
            initial_scopes=initial_scopes,
            initial_execution_mode=initial_execution_mode.value,
            issued_at_ns=now_ns,
            expires_at_ns=exp_ns,
        )
        sig_0 = hmac.new(self._root_key, genesis_bytes, hashlib.sha256).hexdigest()

        # Genesis AS-Path hop
        path_msg = f"{origin_agent_id}:{origin_org_domain}:{turn_id}:{now_ns}:GENESIS".encode("utf-8")
        hop_sig = hmac.new(bytes.fromhex(sig_0), path_msg, hashlib.sha256).hexdigest()
        genesis_hop = ASPathHop(
            asn_agent_id=origin_agent_id,
            org_domain=origin_org_domain,
            turn_id=turn_id,
            timestamp_ns=now_ns,
            prev_path_hash="GENESIS",
            hop_signature_hex=hop_sig,
        )

        return AgentPassportToken(
            nonce_id=nonce_id,
            root_principal_id=root_principal_id,
            tenant_id=tenant_id,
            session_id=session_id,
            turn_id=turn_id,
            initial_scopes=sorted(initial_scopes),
            initial_execution_mode=initial_execution_mode.value,
            issued_at_ns=now_ns,
            expires_at_ns=exp_ns,
            caveats=[],
            as_path=[genesis_hop],
            tail_hmac_hex=sig_0,
        )

    @staticmethod
    def attenuate_passport_at_hop(
        parent_token: AgentPassportToken,
        issuer_agent_id: str,
        target_agent_id: str,
        target_org_domain: str,
        narrowed_scopes: List[str],
        allowed_tools: List[str],
        narrowed_execution_mode: ExecutionMode,
        parameter_constraints: Optional[Dict[str, Any]] = None,
        max_remaining_hops: int = 4,
        hop_ttl_seconds: int = 60,
    ) -> AgentPassportToken:
        """
        Decentralized O(1) hop attenuation: An intermediate agent holding `parent_token`
        attenuates its own tail HMAC without possessing `root_secret_key` and without
        making a network round-trip to the central IdP.
        """
        # 1. Cycle check before attenuation (BGP AS-Path loop prevention)
        visited_agents = {h.asn_agent_id for h in parent_token.as_path}
        if target_agent_id in visited_agents:
            raise PassportVerificationError(
                PassportWireError.A2A_ROUTING_LOOP_DETECTED,
                f"A2A routing cycle detected: target '{target_agent_id}' already in AS-Path {[h.asn_agent_id for h in parent_token.as_path]}",
            )

        now_ns = time.time_ns()
        exp_ns = min(parent_token.expires_at_ns, now_ns + int(hop_ttl_seconds * 1_000_000_000))
        hop_idx = len(parent_token.caveats) + 1

        new_caveat = Caveat(
            hop_index=hop_idx,
            issuer_agent_id=issuer_agent_id,
            target_agent_id=target_agent_id,
            allowed_scopes=sorted(narrowed_scopes),
            allowed_tools=sorted(allowed_tools),
            execution_mode=narrowed_execution_mode.value,
            parameter_constraints=parameter_constraints or {},
            max_remaining_hops=max_remaining_hops,
            issued_at_ns=now_ns,
            expires_at_ns=exp_ns,
        )

        # Chained HMAC: sig_i = HMAC(bytes(sig_{i-1}), canonical_bytes(caveat_i))
        prev_key = bytes.fromhex(parent_token.tail_hmac_hex)
        new_tail_hmac = hmac.new(prev_key, new_caveat.to_canonical_bytes(), hashlib.sha256).hexdigest()

        # Chained AS-Path hop bound to the new caveat state
        prev_path_digest = hashlib.sha256(
            json.dumps([h.to_dict() for h in parent_token.as_path], sort_keys=True).encode("utf-8")
        ).hexdigest()
        path_msg = f"{target_agent_id}:{target_org_domain}:{parent_token.turn_id}:{now_ns}:{prev_path_digest}".encode("utf-8")
        hop_sig = hmac.new(bytes.fromhex(new_tail_hmac), path_msg, hashlib.sha256).hexdigest()

        new_hop = ASPathHop(
            asn_agent_id=target_agent_id,
            org_domain=target_org_domain,
            turn_id=parent_token.turn_id,
            timestamp_ns=now_ns,
            prev_path_hash=prev_path_digest,
            hop_signature_hex=hop_sig,
        )

        return AgentPassportToken(
            nonce_id=parent_token.nonce_id,
            root_principal_id=parent_token.root_principal_id,
            tenant_id=parent_token.tenant_id,
            session_id=parent_token.session_id,
            turn_id=parent_token.turn_id,
            initial_scopes=list(parent_token.initial_scopes),
            initial_execution_mode=parent_token.initial_execution_mode,
            issued_at_ns=parent_token.issued_at_ns,
            expires_at_ns=parent_token.expires_at_ns,
            caveats=list(parent_token.caveats) + [new_caveat],
            as_path=list(parent_token.as_path) + [new_hop],
            tail_hmac_hex=new_tail_hmac,
        )

    def verify_passport_and_invocation(
        self,
        token: AgentPassportToken,
        invoked_tool: str,
        tool_required_scope: str,
        is_mutating_tool: bool,
        tool_arguments: Dict[str, Any],
        serverless_oidc_token: Optional[str],
        hitl_cosignature_header: Optional[str] = None,
    ) -> Tuple[bool, Optional[DraftLockReceipt], Dict[str, Any]]:
        """
        Executes full line-rate wire verification at the receiving A2A/MCP Gateway:
        1. Dual-Header Presence & Structural Verification
        2. AS-Path Loop & Hop-Depth Verification
        3. Cryptographic HMAC-SHA256 Chain Re-computation & Monotonic Caveat Attenuation Check
        4. Parameter Constraint Enforcement
        5. ExecutionMode & Wire-Level HITL Draft-Lock Interception
        """
        t_start = time.perf_counter_ns()

        # 1. Dual-Header Verification ("Resort Wristband" + Serverless OIDC Transport)
        if not serverless_oidc_token or not serverless_oidc_token.startswith("Bearer eyJ"):
            raise PassportVerificationError(
                PassportWireError.DUAL_HEADER_MISSING,
                "Missing or malformed X-Serverless-Authorization OIDC transport token in dual-header frame",
            )

        # 2. AS-Path Cycle Detection & Temporal Causality Bounds (O(k))
        seen_asns: Set[str] = set()
        prev_ts_ns = token.issued_at_ns
        for hop in token.as_path:
            if hop.asn_agent_id in seen_asns:
                raise PassportVerificationError(
                    PassportWireError.A2A_ROUTING_LOOP_DETECTED,
                    f"Cyclic AS-Path vector rejected on wire: duplicate agent ASN '{hop.asn_agent_id}'",
                )
            if hop.timestamp_ns < prev_ts_ns or hop.timestamp_ns > token.expires_at_ns:
                raise PassportVerificationError(
                    PassportWireError.A2A_ROUTING_LOOP_DETECTED,
                    f"AS-Path hop '{hop.asn_agent_id}' violates temporal causality window [{token.issued_at_ns}, {token.expires_at_ns}]",
                )
            prev_ts_ns = hop.timestamp_ns
            seen_asns.add(hop.asn_agent_id)

        # 3. Reconstruct Chained HMAC from Root Key & Enforce Monotonic Attenuation
        now_ns = time.time_ns()
        if now_ns > token.expires_at_ns:
            raise PassportVerificationError(
                PassportWireError.MACAROON_SIGNATURE_INVALID,
                "Root AgentPassportToken has expired",
            )

        genesis_bytes = self._compute_genesis_payload(
            nonce_id=token.nonce_id,
            root_principal_id=token.root_principal_id,
            tenant_id=token.tenant_id,
            session_id=token.session_id,
            turn_id=token.turn_id,
            initial_scopes=token.initial_scopes,
            initial_execution_mode=token.initial_execution_mode,
            issued_at_ns=token.issued_at_ns,
            expires_at_ns=token.expires_at_ns,
        )
        current_sig = hmac.new(self._root_key, genesis_bytes, hashlib.sha256).hexdigest()
        for caveat in token.caveats:
            current_sig = hmac.new(
                bytes.fromhex(current_sig),
                caveat.to_canonical_bytes(),
                hashlib.sha256,
            ).hexdigest()

        # Constant-time tail HMAC comparison BEFORE semantic caveat checks (no unauthenticated error oracle)
        if not hmac.compare_digest(current_sig, token.tail_hmac_hex):
            raise PassportVerificationError(
                PassportWireError.MACAROON_SIGNATURE_INVALID,
                "Cryptographic HMAC-SHA256 macaroon tail signature mismatch (tampered caveats or forged token)",
            )

        effective_scopes: Set[str] = set(token.initial_scopes)
        effective_mode = ExecutionMode(token.initial_execution_mode)
        effective_tools: Optional[Set[str]] = None
        effective_constraints: Dict[str, Any] = {}
        remaining_hops = 10

        for idx, caveat in enumerate(token.caveats):
            if caveat.hop_index != idx + 1:
                raise PassportVerificationError(
                    PassportWireError.MACAROON_SIGNATURE_INVALID,
                    f"Out-of-order caveat hop_index {caveat.hop_index} at position {idx + 1}",
                )
            if now_ns > caveat.expires_at_ns:
                raise PassportVerificationError(
                    PassportWireError.MACAROON_SIGNATURE_INVALID,
                    f"Caveat at hop {caveat.hop_index} has expired",
                )

            # Sender-Constrained BGPsec-style Target-Agent Commitment:
            # Parent caveat C_idx commits to target_agent_id == as_path[idx + 1].asn_agent_id
            if idx + 1 < len(token.as_path):
                if caveat.target_agent_id != token.as_path[idx + 1].asn_agent_id:
                    raise PassportVerificationError(
                        PassportWireError.A2A_ROUTING_LOOP_DETECTED,
                        f"Sender-constrained target binding mismatch at hop {caveat.hop_index}: "
                        f"expected '{caveat.target_agent_id}', got '{token.as_path[idx + 1].asn_agent_id}'",
                    )

            # Monotonic Scope Narrowing Check: caveat scopes MUST be a subset of parent effective_scopes
            caveat_scopes = set(caveat.allowed_scopes)
            if not caveat_scopes.issubset(effective_scopes):
                illegitimate = caveat_scopes - effective_scopes
                raise PassportVerificationError(
                    PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED,
                    f"Hop {caveat.hop_index} attempted privilege escalation via unauthorized scopes: {sorted(illegitimate)}",
                )
            effective_scopes = caveat_scopes

            # Monotonic Tool Narrowing Check
            caveat_tools = set(caveat.allowed_tools)
            if effective_tools is not None and not caveat_tools.issubset(effective_tools):
                illegitimate_tools = caveat_tools - effective_tools
                raise PassportVerificationError(
                    PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED,
                    f"Hop {caveat.hop_index} attempted tool widening: {sorted(illegitimate_tools)}",
                )
            effective_tools = caveat_tools

            # Monotonic ExecutionMode Check
            caveat_mode = ExecutionMode(caveat.execution_mode)
            if not effective_mode.can_attenuate_to(caveat_mode):
                raise PassportVerificationError(
                    PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED,
                    f"Hop {caveat.hop_index} attempted ExecutionMode escalation from {effective_mode.value} to {caveat_mode.value}",
                )
            effective_mode = caveat_mode

            # Hop Depth Budget Check: h_i in N_0 (remaining hops AFTER hop i: h_i >= 0 and strictly decreasing)
            if caveat.max_remaining_hops >= remaining_hops and idx > 0:
                raise PassportVerificationError(
                    PassportWireError.A2A_ROUTING_LOOP_DETECTED,
                    f"Hop {caveat.hop_index} violated strictly decreasing hop budget",
                )
            remaining_hops = caveat.max_remaining_hops
            if remaining_hops < 0:
                raise PassportVerificationError(
                    PassportWireError.A2A_ROUTING_LOOP_DETECTED,
                    f"Hop depth exhausted at hop {caveat.hop_index}",
                )

            # Conjunctive per-hop parameter predicate enforcement (every hop i in 1..k must be satisfied)
            for param_key, constraint_val in caveat.parameter_constraints.items():
                if param_key in effective_constraints and effective_constraints[param_key] != constraint_val:
                    if isinstance(effective_constraints[param_key], list) and isinstance(constraint_val, list):
                        if not set(constraint_val).issubset(set(effective_constraints[param_key])):
                            raise PassportVerificationError(
                                PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED,
                                f"Hop {caveat.hop_index} widened parameter constraint '{param_key}'",
                            )
                    elif isinstance(effective_constraints[param_key], (int, float)) and isinstance(constraint_val, (int, float)):
                        if constraint_val > effective_constraints[param_key]:
                            raise PassportVerificationError(
                                PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED,
                                f"Hop {caveat.hop_index} exceeded numeric parameter ceiling '{param_key}'",
                            )
                effective_constraints[param_key] = constraint_val

                # Evaluate hop i predicate directly against tool_arguments (conjunctive across i=1..k)
                if param_key.startswith("max_"):
                    arg_name = param_key[len("max_"):]
                    if arg_name in tool_arguments and float(tool_arguments[arg_name]) > float(constraint_val):
                        raise PassportVerificationError(
                            PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED,
                            f"Argument '{arg_name}'={tool_arguments[arg_name]} violates hop {caveat.hop_index} ceiling {constraint_val}",
                        )
                elif param_key in tool_arguments:
                    actual = tool_arguments[param_key]
                    if isinstance(constraint_val, list) and actual not in constraint_val:
                        raise PassportVerificationError(
                            PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED,
                            f"Argument '{param_key}'='{actual}' not in hop {caveat.hop_index} allowed values {constraint_val}",
                        )

        # 4. Verify Target Tool & Scope Authorization against Attenuated Set
        if tool_required_scope not in effective_scopes:
            raise PassportVerificationError(
                PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED,
                f"Tool '{invoked_tool}' requires scope '{tool_required_scope}', not in attenuated set {sorted(effective_scopes)}",
            )

        if effective_tools is not None and invoked_tool not in effective_tools:
            raise PassportVerificationError(
                PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED,
                f"Tool '{invoked_tool}' is excluded by hop-attenuated tool whitelist {sorted(effective_tools)}",
            )

        # 5. Enforce ExecutionMode & Wire-Level HITL Draft-Lock Protocol
        draft_receipt: Optional[DraftLockReceipt] = None
        if is_mutating_tool:
            if effective_mode == ExecutionMode.READ_ONLY:
                raise PassportVerificationError(
                    PassportWireError.CAVEAT_PRIVILEGE_ESCALATION_BLOCKED,
                    f"Mutating tool '{invoked_tool}' blocked: passport attenuated to READ_ONLY",
                )
            elif effective_mode == ExecutionMode.DRAFT_STAGED and not hitl_cosignature_header:
                # Stage as Draft and emit DraftLockReceipt with 24h async draft TTL (tau_draft_exp)
                payload_hash = hashlib.sha256(
                    json.dumps(tool_arguments, sort_keys=True).encode("utf-8")
                ).hexdigest()
                draft_id = f"DRAFT-{secrets.token_hex(8)}"
                active_agent = token.as_path[-1].asn_agent_id if token.as_path else "unknown"
                draft_exp_ns = now_ns + 86_400_000_000_000  # 24 hours
                lock_msg = (
                    f"{token.nonce_id}:{draft_id}:{invoked_tool}:{payload_hash}:"
                    f"{token.root_principal_id}:{active_agent}:{draft_exp_ns}"
                ).encode("utf-8")
                lock_hmac = hmac.new(self._hitl_key, lock_msg, hashlib.sha256).hexdigest()
                draft_receipt = DraftLockReceipt(
                    draft_id=draft_id,
                    tool_name=invoked_tool,
                    staged_payload_sha256=payload_hash,
                    principal_id=token.root_principal_id,
                    agent_id=active_agent,
                    execution_mode=effective_mode.value,
                    created_at_ns=now_ns,
                    requires_human_cosignature=True,
                    lock_hmac_hex=lock_hmac,
                    expires_at_ns=draft_exp_ns,
                    nonce_id=token.nonce_id,
                )
            elif effective_mode in (ExecutionMode.HITL_COSIGNED, ExecutionMode.DRAFT_STAGED):
                # EU AI Act Article 14 Mandate or Staged Draft Release: require valid X-HITL-Human-Cosignature header
                payload_hash = hashlib.sha256(
                    json.dumps(tool_arguments, sort_keys=True).encode("utf-8")
                ).hexdigest()
                expected_cosig = self.compute_human_cosignature(
                    principal_id=token.root_principal_id,
                    tool_name=invoked_tool,
                    payload_sha256=payload_hash,
                    turn_id=token.turn_id,
                )
                if not hitl_cosignature_header or not hmac.compare_digest(expected_cosig, hitl_cosignature_header):
                    raise PassportVerificationError(
                        PassportWireError.HITL_DRAFT_COSIGNATURE_REQUIRED,
                        f"EU AI Act Art. 14 violation: mutating tool '{invoked_tool}' requires valid X-HITL-Human-Cosignature wire header",
                    )

        latency_us = (time.perf_counter_ns() - t_start) / 1000.0
        telemetry = {
            "verification_latency_us": round(latency_us, 3),
            "hop_count": len(token.caveats),
            "as_path_length": len(token.as_path),
            "effective_mode": effective_mode.value,
            "draft_staged": draft_receipt is not None,
        }
        return True, draft_receipt, telemetry

    def compute_human_cosignature(
        self,
        principal_id: str,
        tool_name: str,
        payload_sha256: str,
        turn_id: str,
    ) -> str:
        """
        Generates the out-of-band human reviewer co-signature token transmitted
        in X-HITL-Human-Cosignature to unlock a HITL_COSIGNED or DRAFT_STAGED mutation.
        """
        msg = f"HITL_ART14_APPROVAL:{principal_id}:{tool_name}:{payload_sha256}:{turn_id}".encode("utf-8")
        return hmac.new(self._hitl_key, msg, hashlib.sha256).hexdigest()
