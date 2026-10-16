"""
Agent-Passport: Wire-Level Cryptographic Hop-Attenuated Delegation,
Dual-Header Zero-Trust Passthrough, AS-Path Loop Prevention, and
HITL Draft-Lock Protocol for Cross-Domain A2A & MCP Multi-Agent Swarms.

Module: passport_types.py
Defines formal protocol data structures, wire headers, JSON-RPC error codes,
and .well-known/agent.json security extension schemas.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import json


class ExecutionMode(str, Enum):
    """
    Monotonically ordered execution capability modes enforced on the wire.
    Ordering: READ_ONLY (0) < DRAFT_STAGED (1) < HITL_COSIGNED (2) < AUTONOMOUS_MUTATION (3)
    """
    READ_ONLY = "READ_ONLY"
    DRAFT_STAGED = "DRAFT_STAGED"
    HITL_COSIGNED = "HITL_COSIGNED"
    AUTONOMOUS_MUTATION = "AUTONOMOUS_MUTATION"

    @property
    def privilege_rank(self) -> int:
        ranks = {
            ExecutionMode.READ_ONLY: 0,
            ExecutionMode.DRAFT_STAGED: 1,
            ExecutionMode.HITL_COSIGNED: 2,
            ExecutionMode.AUTONOMOUS_MUTATION: 3,
        }
        return ranks[self]

    def can_attenuate_to(self, target: "ExecutionMode") -> bool:
        """
        Monotonic attenuation invariant: a downstream hop may only maintain
        or strictly reduce execution privilege rank (target.rank <= self.rank).
        """
        return target.privilege_rank <= self.privilege_rank


class PassportWireError(int, Enum):
    """
    Standardized JSON-RPC 2.0 / HTTP wire error codes for Agent-Passport.
    Observable externally via black-box protocol probing and Wireshark captures.
    """
    DUAL_HEADER_MISSING = -32095
    MACAROON_SIGNATURE_INVALID = -32096
    CAVEAT_PRIVILEGE_ESCALATION_BLOCKED = -32097
    A2A_ROUTING_LOOP_DETECTED = -32098
    HITL_DRAFT_COSIGNATURE_REQUIRED = -32099


# Standardized Wire Header Constants (Competitor Detectability Boundary)
HDR_AUTHORIZATION = "Authorization"
HDR_SERVERLESS_AUTH = "X-Serverless-Authorization"
HDR_PASSPORT_MACAROON = "X-Agent-Passport-Macaroon"
HDR_AS_PATH_VECTOR = "X-A2A-Origin-Path-Vector"
HDR_EXECUTION_MODE = "X-Agent-Execution-Mode"
HDR_DRAFT_LOCK_TOKEN = "X-HITL-Draft-Lock-Token"
HDR_HITL_COSIGNATURE = "X-HITL-Human-Cosignature"
HDR_ZEROIZATION_RECEIPT = "X-Passport-Zeroization-Receipt"


@dataclass(frozen=True)
class Caveat:
    """
    Contextual attenuation caveat appended at delegation hop i.
    Hashed into the HMAC-SHA256 chain: sig_i = HMAC(sig_{i-1}, canonical_json(caveat_i)).
    """
    hop_index: int
    issuer_agent_id: str
    target_agent_id: str
    allowed_scopes: List[str]
    allowed_tools: List[str]
    execution_mode: str  # ExecutionMode value
    parameter_constraints: Dict[str, Any]  # e.g. {"company_code": ["US01"], "max_amount_usd": 50000}
    max_remaining_hops: int
    issued_at_ns: int
    expires_at_ns: int

    def to_canonical_bytes(self) -> bytes:
        payload = {
            "hop_index": self.hop_index,
            "issuer_agent_id": self.issuer_agent_id,
            "target_agent_id": self.target_agent_id,
            "allowed_scopes": sorted(self.allowed_scopes),
            "allowed_tools": sorted(self.allowed_tools),
            "execution_mode": self.execution_mode,
            "parameter_constraints": self.parameter_constraints,
            "max_remaining_hops": self.max_remaining_hops,
            "issued_at_ns": self.issued_at_ns,
            "expires_at_ns": self.expires_at_ns,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class ASPathHop:
    """
    BGP-style Autonomous Agent System Path Vector element.
    Prevents cyclic A2A delegation loops (e.g. before_tool_callback auth storms).
    """
    asn_agent_id: str
    org_domain: str
    turn_id: str
    timestamp_ns: int
    prev_path_hash: str
    hop_signature_hex: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentPassportToken:
    """
    Wire-serializable Hop-Attenuated Macaroon Passport carried in
    X-Agent-Passport-Macaroon and Authorization headers.
    """
    nonce_id: str
    root_principal_id: str
    tenant_id: str
    session_id: str
    turn_id: str
    initial_scopes: List[str]
    initial_execution_mode: str
    issued_at_ns: int
    expires_at_ns: int
    caveats: List[Caveat] = field(default_factory=list)
    as_path: List[ASPathHop] = field(default_factory=list)
    tail_hmac_hex: str = ""
    mode: str = "A"

    def to_wire_json(self) -> str:
        data = {
            "mode": self.mode,
            "nonce_id": self.nonce_id,
            "root_principal_id": self.root_principal_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "turn_id": self.turn_id,
            "initial_scopes": sorted(self.initial_scopes),
            "initial_execution_mode": self.initial_execution_mode,
            "issued_at_ns": self.issued_at_ns,
            "expires_at_ns": self.expires_at_ns,
            "caveats": [asdict(c) for c in self.caveats],
            "as_path": [h.to_dict() for h in self.as_path],
            "tail_hmac_hex": self.tail_hmac_hex,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_wire_json(cls, raw_json: str) -> "AgentPassportToken":
        d = json.loads(raw_json)
        caveats = [Caveat(**c) for c in d.get("caveats", [])]
        as_path = [ASPathHop(**h) for h in d.get("as_path", [])]
        return cls(
            nonce_id=d["nonce_id"],
            root_principal_id=d["root_principal_id"],
            tenant_id=d["tenant_id"],
            session_id=d["session_id"],
            turn_id=d["turn_id"],
            initial_scopes=d["initial_scopes"],
            initial_execution_mode=d["initial_execution_mode"],
            issued_at_ns=d["issued_at_ns"],
            expires_at_ns=d["expires_at_ns"],
            caveats=caveats,
            as_path=as_path,
            tail_hmac_hex=d["tail_hmac_hex"],
            mode=d.get("mode", "A"),
        )


@dataclass(frozen=True)
class DraftLockReceipt:
    """
    Wire receipt emitted when an agent operating in DRAFT_STAGED or HITL_COSIGNED
    mode attempts to invoke a mutating tool (e.g., sendMail, postSAPJournal, publishHRRating).
    Enforces EU AI Act Article 14 and enterprise CMP Draft-Only policies on the wire.
    """
    draft_id: str
    tool_name: str
    staged_payload_sha256: str
    principal_id: str
    agent_id: str
    execution_mode: str
    created_at_ns: int
    requires_human_cosignature: bool
    lock_hmac_hex: str
    expires_at_ns: int = 0
    nonce_id: str = ""

    def to_wire_header(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class ZeroizationReceipt:
    """
    Cryptographic attestation emitted in X-Passport-Zeroization-Receipt proving
    that ephemeral turn-scoped bearer buffers were overwritten with 0x00 in RAM
    upon turn completion (solving ADK async context residue).
    """
    turn_id: str
    agent_id: str
    buffer_address_hex: str
    bytes_zeroized: int
    post_zero_sha256: str
    timestamp_ns: int
    attestation_hmac_hex: str
    pre_zero_hmac_hex: str = ""
    nonce_id: str = ""

    def to_wire_header(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


def build_agent_card_security_descriptor(
    agent_id: str,
    org_domain: str,
    supported_modes: List[ExecutionMode],
    max_delegation_depth: int = 5,
) -> Dict[str, Any]:
    """
    Generates the public /.well-known/agent.json A2A AgentCard descriptor
    advertising Agent-Passport dual-header and loop-prevention requirements.
    Solves Teradata Marketplace static analysis 'Open Authentication' blocker.
    """
    return {
        "name": agent_id,
        "organization": org_domain,
        "protocolVersion": "A2A-2026-10 / FastMCP-2024-11-05",
        "authentication": {
            "schemes": ["Bearer", "AgentPassport-v1"],
            "dualHeaderRequired": True,
            "requiredHeaders": [
                HDR_AUTHORIZATION,
                HDR_SERVERLESS_AUTH,
                HDR_PASSPORT_MACAROON,
                HDR_AS_PATH_VECTOR,
            ],
            "unauthenticatedRejectionCodes": [401, 403],
        },
        "agentPassport": {
            "version": "1.0.0",
            "hmacAlgorithm": "HMAC-SHA256",
            "asPathLoopEnforcement": "STRICT_FAIL_CLOSED",
            "maxDelegationDepth": max_delegation_depth,
            "supportedExecutionModes": [m.value for m in supported_modes],
            "turnScopedMemoryZeroization": True,
            "euAiActArt14HitlLock": True,
        },
    }
