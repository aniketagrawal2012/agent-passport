# Agent-Passport: Cryptographic Hop-Attenuated Macaroon Delegation, AS-Path Loop Prevention, and Wire-Enforced HITL Draft Locks for A2A & MCP Swarms

[![Tests](https://img.shields.io/badge/tests-5%2F5%20passing-brightgreen)](#quick-start--reproduction)
[![Benchmark](https://img.shields.io/badge/benchmark-N%3D1%2C200%20traces-blue)](#empirical-benchmark-results-n--1200-traces)
[![Latency](https://img.shields.io/badge/mean%20latency-0.2962%20ms%20(150x%20faster)-success)](#per-hop-latency-scaling)
[![Protocol](https://img.shields.io/badge/wire%20protocol-A2A%20v1.0%20%2B%20MCP%20JSON--RPC%202.0-orange)](#wire-protocol-specification)

**Agent-Passport** is a zero-trust cryptographic wire protocol and gateway middleware for multi-agent swarms speaking the **Agent2Agent (A2A)** protocol and **Model Context Protocol (MCP)** across serverless infrastructures (such as Google Cloud Run and Vertex AI Agent Engine).

---

## Core Architectural Contributions

1. **Dual-Header Serverless Passthrough + Non-Interactive Chained HMAC-SHA256 Macaroon Delegation**:
   - Decouples cloud container IAM authentication (`X-Serverless-Authorization: Bearer <OIDC_Token>`) from user OAuth bearer passthrough (`Authorization: Bearer <User_OAuth>`) and contextual capability attenuation (`X-Agent-Passport-Macaroon`).
   - Enables any intermediate A2A agent $A_i$ to non-interactively narrow allowed OAuth scopes ($S_i \subseteq S_{i-1}$), execution modes ($m_i \preceq m_{i-1}$), parameter predicates ($P_i$), and remaining hop budgets ($h_i < h_{i-1}$) in $\mathcal{O}(1)$ local CPU time ($\approx 4.2~\mu\text{s}$ per hop) without contacting a central Identity Provider (IdP).
2. **BGP-Inspired Autonomous System Path-Vector (`AS-PATH`) Loop Prevention**:
   - Embeds a cryptographically bound routing vector (`X-A2A-Origin-Path-Vector`) into each chained HMAC hop signature, detecting and terminating cyclic multi-agent delegation graphs in $\mathcal{O}(k)$ stateless gateway time via JSON-RPC error `-32097`.
3. **Wire-Enforced Stage-and-Hold Human-in-the-Loop (HITL) Draft Lock**:
   - Elevates organizational Change Management (CMP) `"Draft-Only"` rules and **EU AI Act Article 14 (Human Oversight)** requirements from probabilistic system prompt instructions to deterministic wire invariants.
   - Mutating MCP calls under `DRAFT_STAGED` caveats are intercepted at the gateway, persisted to a SQLite WAL staging vault, and returned with `HTTP 202 Accepted` and a signed `X-HITL-Draft-Lock-Token`.
   - Mutating calls under `COMMIT_WITH_HITL` caveats without a valid cryptographic human co-signature (`X-HITL-Human-Cosignature`) over the exact canonical payload digest $\operatorname{SHA-256}(\operatorname{Canon}(\text{params}))$ are deterministically rejected with `HTTP 428 Precondition Required` (JSON-RPC `-32095`).
4. **Turn-Scoped Physical RAM Zeroization (`ctypes.memset`)**:
   - Allocates sensitive OAuth bearer credentials inside mutable contiguous byte buffers (`TurnScopedZeroizingBuffer`) and overwrites physical memory in-place with `0x00` bytes via C-level `ctypes.memset` upon turn exit, emitting a signed `X-Passport-Zeroization-Receipt`.

---

## Wire Protocol Specification

### HTTP/2 Request & Response Headers
```http
POST /mcp/v1/tools/call HTTP/2
Host: m365-mcp-gateway-uc.a.run.app
Authorization: Bearer <USER_OAUTH_PASSTHROUGH_TOKEN>
X-Serverless-Authorization: Bearer <CLOUD_RUN_OIDC_JWT>
X-Agent-Passport-Macaroon: {"nonce_id":"a9f1...","root_principal_id":"ppmd_leader@deloitte.com","caveats":[{"hop_index":1,"allowed_scopes":["m365.mail.send"],"execution_mode":"DRAFT_STAGED","max_remaining_hops":2}],"as_path":[...],"tail_hmac_hex":"8f4e..."}
X-A2A-Origin-Path-Vector: [{"as_agent_id":"ag-chief-of-staff","trust_domain":"gcp.us-central1.deloitte","hop_timestamp_ms":1760515200112}]

HTTP/2 202 Accepted
Content-Type: application/json
X-Agent-Execution-Mode: DRAFT_STAGED
X-HITL-Draft-Lock-Token: {"draft_id":"DRAFT-7c91a04b","requires_human_cosignature":true,"staged_payload_sha256":"e3b0...","lock_hmac_hex":"4d12..."}
X-Passport-Zeroization-Receipt: {"buffer_address_hex":"0x104a2c080","bytes_zeroized":2205,"post_zero_sha256":"7d86...","attestation_hmac_hex":"9b01..."}
```

### Standard JSON-RPC 2.0 Error Codes
| Error Code | Constant | HTTP Status | Description |
| :--- | :--- | :--- | :--- |
| `-32099` | `ERR_MACAROON_HMAC_INVALID` | `403 Forbidden` | Chained HMAC-SHA256 signature verification failed or token expired |
| `-32098` | `ERR_MONOTONIC_SCOPE_VIOLATION` | `403 Forbidden` | Non-monotonic scope escalation ($S_i \not\subseteq S_{i-1}$) or mode upgrade ($m_i \not\preceq m_{i-1}$) |
| `-32097` | `ERR_BGP_AS_PATH_LOOP_DETECTED` | `409 Conflict` | Duplicate `as_agent_id` detected in `X-A2A-Origin-Path-Vector` |
| `-32096` | `ERR_HITL_DRAFT_LOCK_STAGED` | `202 Accepted` | Mutating tool call intercepted and staged in SQLite WAL under `DRAFT_STAGED` |
| `-32095` | `ERR_HITL_COSIGNATURE_REQUIRED` | `428 Precondition Required` | Missing or invalid `X-HITL-Human-Cosignature` under `COMMIT_WITH_HITL` |

---

## Empirical Benchmark Results ($N = 1,200$ Traces)

Evaluated across **$N = 1,200$ stratified enterprise multi-agent traces** (1 to 4 delegation hops across 6 workload strata) over real OS kernel full-duplex UNIX domain sockets (`socket.socketpair(AF_UNIX, SOCK_STREAM)`) and persistent SQLite WAL storage:

| Architecture | Mean Latency (ms) | Median $p_{50}$ (ms) | Tail $p_{95}$ (ms) | Tail $p_{99}$ (ms) | Privilege Escalation Blocked | CMP Draft Lock Enforced | EU AI Act Art. 14 HITL | BGP AS-Path Loop Blocked | Physical RAM Zeroized |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **B1: Ambient OAuth Forwarding (RFC 6750)** | 0.1489 | 0.1422 | 0.1895 | 0.2314 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| **B2: Centralized IdP Exchange (RFC 8693)** | 27.6841 | 24.8120 | 46.5190 | 48.9402 | **100.0%** | 0.0% | 0.0% | 0.0% | 0.0% |
| **B3: Client `before_tool_callback`** | 37.3912 | 34.1180 | 62.1045 | 66.8910 | 82.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| **B4: Prompt-Only HITL + Static RBAC** | 0.1612 | 0.1538 | 0.2041 | 0.2580 | 41.3% | 24.0% | 18.0% | 0.0% | 0.0% |
| **Agent-Passport (Ours)** | **0.2962** | **0.2798** | **0.4216** | **0.5295** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **100.0%** |

### Per-Hop Latency Scaling
| Delegation Depth ($k$ Hops) | Agent-Passport Mean (ms) | Centralized RFC 8693 IdP (ms) | Client Callback B3 (ms) | Speedup vs. RFC 8693 |
| :---: | ---: | ---: | ---: | :---: |
| **$k = 1$ Hop** | `0.3125 ms` | `10.4210 ms` | `13.8920 ms` | **33.3x** |
| **$k = 2$ Hops** | `0.3055 ms` | `20.8412 ms` | `27.8105 ms` | **68.2x** |
| **$k = 3$ Hops** | `0.2950 ms` | `31.2190 ms` | `41.7450 ms` | **105.8x** |
| **$k = 4$ Hops** | `0.2768 ms` | `41.6155 ms` | `55.6601 ms` | **150.3x** |

---

## Repository Structure

```text
agent-passport/
├── passport_types.py                 # Wire protocol structures, headers, error codes & .well-known/agent.json schema
├── macaroon_engine.py                # Chained HMAC-SHA256 engine, AS-PATH verifier, HITL signer & ctypes RAM zeroizer
├── gateway_middleware.py             # A2A & FastMCP HTTP/2 JSON-RPC 2.0 gateway + SQLite WAL staging vault
├── test_agent_passport.py            # Unit test suite verifying Theorems 1-4 (5/5 passing)
├── run_live_benchmark.py             # Live UNIX socket + SQLite WAL benchmark harness (N = 1,200 traces)
├── generate_plots.py                 # Publication-grade 300-DPI PDF/PNG figure generator
├── verify_tex.py                     # Automated LaTeX syntax, citation, and cross-reference auditor
├── agent_passport_paper.tex          # IEEEtran LaTeX research manuscript source
├── Agent_Passport_Paper.pdf          # Compiled IEEEtran camera-ready PDF manuscript
├── GOOGLE_IDF_PORTAL_SUBMISSION.md   # Complete 10-Screen Google Invention Disclosure Form (IDF) dossier
├── datasets/
│   ├── benchmark_summary.json        # Aggregated empirical metrics across all 5 architectures & 6 strata
│   ├── benchmark_traces_1200.csv     # Per-trace telemetry for all N = 1,200 multi-agent executions
│   └── passport_audit_ledger.db      # Persistent SQLite WAL draft staging & wire audit ledger
└── plots/
    ├── fig1_hop_latency_scaling.pdf  # Per-hop latency scaling chart (vector PDF + 300-DPI PNG)
    ├── fig2_security_governance_matrix.pdf
    └── fig3_tail_latency_percentiles.pdf
```

---

## Quick Start & Reproduction

```bash
# 1. Run formal unit tests verifying Theorems 1-4
python3 test_agent_passport.py -v

# 2. Execute the N = 1,200 live socket & SQLite WAL benchmark suite
python3 run_live_benchmark.py

# 3. Regenerate 300-DPI publication figures
python3 generate_plots.py

# 4. Audit LaTeX manuscript syntax and citations
python3 verify_tex.py
```

---

## Author
**Aniket Agrawal**  
Google Cloud, Customer Engineering & AI Architecture (`aniketagrawal@google.com`)
