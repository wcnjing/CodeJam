# Graph Report - CodeJam  (2026-08-29)

## Corpus Check
- 76 files · ~72,511 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 627 nodes · 1129 edges · 44 communities (34 shown, 10 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 61 edges (avg confidence: 0.81)
- Token cost: 236,939 input · 0 output

## Community Hubs (Navigation)
- AgentService Core Module
- AgentService Test Suite
- Fastify HTTP API
- Capability Extraction Engine
- Server Package Config
- Web API Client & App
- Root Package Scripts
- Web Package Config
- Command Policy & Tests
- Web TypeScript Config
- Threat Model CLI
- Local POC Startup Script
- Evaluation Summary & Benchmark
- Policy Corpus Definitions
- Policy Corpus & Eval Engine
- Base TypeScript Config
- Server TypeScript Config
- Kill Switch Plan & Threats
- Policy Evaluation Defects
- Security Benchmark CLI
- Playground Screenshot Concepts
- Held-Approval Screenshot Concepts
- Security Evaluation Screenshot
- Governance & Threat Register
- Deployment & Setup Docs
- Architecture Components
- Kill Switch Overview & Bypass
- Red-Team Probe Script
- Hackathon Extension Tracks
- Volcengine Deployment Config
- Security Policy Docs
- Mock Collector Script
- Prompt Injection Planting Script
- Human Approval & Host Grant
- Existing-ECS Deploy Script
- Contributing Validation
- Hackathon Deliverables & Evaluation
- Local Bootstrap Script
- Web Index Root
- Docker Compose Launchpad
- README Config Table
- Credential Boundary Note
- README How-It-Works

## God Nodes (most connected - your core abstractions)
1. `AgentService` - 29 edges
2. `AgentRunner` - 20 edges
3. `createApp()` - 19 edges
4. `evaluateCommand()` - 17 edges
5. `loadConfig()` - 16 edges
6. `WorkspaceManager` - 16 edges
7. `compilerOptions` - 16 edges
8. `policyContextFrom()` - 15 edges
9. `PolicyViolationError` - 15 edges
10. `JsonStore` - 15 edges

## Surprising Connections (you probably didn't know these)
- `PolicyDecision Type` --references--> `PolicyDecision`  [EXTRACTED]
  docs/KILL_SWITCH_PLAN.md → apps/server/src/types.ts
- `command-policy.ts Design` --references--> `evaluateCommand()`  [EXTRACTED]
  docs/KILL_SWITCH_PLAN.md → apps/server/src/command-policy.ts
- `Command Policy Engine` --references--> `evaluateCommand()`  [EXTRACTED]
  README.md → apps/server/src/command-policy.ts
- `Named Operational Gaps` --references--> `redactCommand()`  [EXTRACTED]
  docs/OPERATIONAL_GOVERNANCE.md → apps/server/src/command-policy.ts
- `bench:security Policy-Decision Benchmark` --references--> `guardedEvaluate()`  [EXTRACTED]
  docs/POLICY_EVALUATION.md → apps/server/src/command-policy.ts

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Hackathon Track Menu** — docs_hackathon_extension_guide_glass_box, docs_hackathon_extension_guide_bouncer, docs_hackathon_extension_guide_kill_switch, docs_architecture_extension_seams [EXTRACTED 1.00]
- **Kill Switch Threat Register (TM-AGENT / TM-OPS)** — docs_threat_model_tm_agent_001, docs_threat_model_tm_agent_002, docs_threat_model_tm_agent_003, docs_threat_model_tm_agent_004, docs_threat_model_tm_agent_005, docs_threat_model_tm_agent_006, docs_threat_model_tm_ops_001 [EXTRACTED 1.00]
- **Command Policy Enforcement Pipeline** — apps_server_src_command_policy_evaluatecommand [EXTRACTED 1.00]
- **Network Egress Approval Workflow** — docs_assets_held_approval_invoice_builder_agent, docs_assets_held_approval_curl_command, docs_assets_held_approval_network_egress_denied, docs_assets_held_approval_human_approval_required_panel, docs_assets_held_approval_approve_deny_control [EXTRACTED 1.00]
- **Invoice Builder Demo Task Execution** — docs_assets_playground_invoice_builder_agent, docs_assets_playground_hello_ts_demo_task, docs_assets_playground_hello_ts, docs_assets_playground_hello_test_ts, docs_assets_playground_package_json [EXTRACTED 1.00]
- **Security evaluation metrics jointly characterize policy safety** — docs_assets_security_evaluation_no_middleware_finding, docs_assets_security_evaluation_attack_block_rate_metric, docs_assets_security_evaluation_secret_channel_metric [INFERRED 0.85]

## Communities (44 total, 10 thin omitted)

### Community 0 - "AgentService Core Module"
Cohesion: 0.08
Nodes (29): AgentService, now(), makeService(), createApp(), service, makeService(), isReviewableRule(), isArkConfigured() (+21 more)

### Community 1 - "AgentService Test Suite"
Cohesion: 0.07
Nodes (25): BlockingThenHealthyRunner, FakeRunner, MonitoringRunner, MonitorThenFailRunner, RunawayRunner, temporaryDirectories, dirs, EgressGatedRunner (+17 more)

### Community 2 - "Fastify HTTP API"
Cohesion: 0.06
Nodes (33): agentIdParams, approvalDecisionBody, approvalIdParams, createAgentBody, messageBody, runIdParams, updateAgentBody, dirs (+25 more)

### Community 3 - "Capability Extraction Engine"
Cohesion: 0.08
Nodes (48): ANY_URL, Capability, CapabilityEvidence, CONDITIONAL_NETWORK, extractHosts(), findProtectedSecret(), hasNamedArkAccess(), hasShellArkDereference() (+40 more)

### Community 4 - "Server Package Config"
Cohesion: 0.06
Nodes (32): dependencies, fastify, @fastify/cors, @fastify/static, zod, devDependencies, tsx, @types/node (+24 more)

### Community 5 - "Web API Client & App"
Cohesion: 0.14
Nodes (20): api, ApiError, request(), setAuthToken(), App(), emptyForm, EvaluationView(), formatTime() (+12 more)

### Community 6 - "Root Package Scripts"
Cohesion: 0.08
Nodes (25): concurrently, description, devDependencies, concurrently, typescript, engines, node, typescript (+17 more)

### Community 7 - "Web Package Config"
Cohesion: 0.08
Nodes (24): dependencies, react, react-dom, vite, @vitejs/plugin-react, devDependencies, @types/react, @types/react-dom (+16 more)

### Community 8 - "Command Policy & Tests"
Cohesion: 0.13
Nodes (20): CapabilityRequest, extractCapabilities(), isTextualUrlOnly(), context, untrustedDestinations(), allowedHostsFrom(), CapabilityRule, describeCapabilities() (+12 more)

### Community 9 - "Web TypeScript Config"
Cohesion: 0.09
Nodes (22): compilerOptions, allowJs, allowSyntheticDefaultImports, esModuleInterop, forceConsistentCasingInFileNames, isolatedModules, jsx, lib (+14 more)

### Community 10 - "Threat Model CLI"
Cohesion: 0.17
Nodes (10): covered, here, mitigated, open, Control, risk(), RiskScore, here (+2 more)

### Community 11 - "Local POC Startup Script"
Cohesion: 0.19
Nodes (14): cleanup(), CODEX_SANDBOX_MODE, CONTAINER_ENGINE, CONTAINER_RUNTIME_IMAGE, CONTAINER_USER, detect_engine(), engine_works(), HOST (+6 more)

### Community 12 - "Evaluation Summary & Benchmark"
Cohesion: 0.24
Nodes (11): buildEvaluationSummary(), EvaluationSummary, latency(), BenchmarkResult, CaseResult, CONTEXT, Decision, Family (+3 more)

### Community 13 - "Policy Corpus Definitions"
Cohesion: 0.14
Nodes (13): BENIGN, CorpusLabel, EVASION_CATEGORIES, EXTERNAL_REVIEW, INTERNAL_RED_TEAM, MALICIOUS_ALTERNATE_CHANNEL, MALICIOUS_DIRECT, MALICIOUS_EVASION (+5 more)

### Community 14 - "Policy Corpus & Eval Engine"
Cohesion: 0.24
Nodes (11): CorpusEntry, POLICY_CORPUS, CategoryScore, DEFAULT_CONTEXT, evaluatePolicy(), EvaluationResult, formatReport(), isBlocked() (+3 more)

### Community 15 - "Base TypeScript Config"
Cohesion: 0.14
Nodes (13): ES2023, compilerOptions, esModuleInterop, exactOptionalPropertyTypes, forceConsistentCasingInFileNames, lib, module, moduleResolution (+5 more)

### Community 16 - "Server TypeScript Config"
Cohesion: 0.17
Nodes (11): compilerOptions, outDir, rootDir, types, exclude, extends, include, node (+3 more)

### Community 17 - "Kill Switch Plan & Threats"
Cohesion: 0.20
Nodes (10): command-policy.ts Design, item.started vs item.completed Timing Confirmation, PolicyDecision Type, TM-AGENT-001: Indirect Prompt Injection, TM-AGENT-002: Secret Exfiltration to Non-Allowlisted Host, TM-AGENT-004: Runaway Execution / Denial of Wallet, Capability Model (NETWORK_EGRESS / SECRET_READ), Command Policy Engine (+2 more)

### Community 18 - "Policy Evaluation Defects"
Cohesion: 0.20
Nodes (10): bench:security Policy-Decision Benchmark, Policy Corpus (171 labeled commands), Defect: Environment Protection at Wrong Layer, Defect: Filename Denylist Masked attacker.example, Defect: Unblocked Bare Reverse Shell, Policy Evaluation Harness (eval:policy), Policy Evaluation Results, Policy-Predicted Escape Rate (+2 more)

### Community 19 - "Security Benchmark CLI"
Cohesion: 0.25
Nodes (6): policyContextFrom(), baseline, escapes, lat, policyLatency(), protectedRun

### Community 20 - "Playground Screenshot Concepts"
Cohesion: 0.31
Nodes (9): Codex CLI Runtime (ep-demo container), hello.test.ts (Vitest test), hello.ts (CLI entry point), TypeScript Hello-World CLI Demo Task, Invoice Builder Agent, package.json (updated with test script), Playground UI Screenshot, Security Evaluation (+1 more)

### Community 21 - "Held-Approval Screenshot Concepts"
Cohesion: 0.29
Nodes (8): Approve & Resume / Deny Control, Codex CLI Runtime (application container), curl https://registry.npmjs.org/react command, Human Approval Required Panel, Invoice Builder Agent, NETWORK-EGRESS-DENIED Violation, Agent Policy (allowlist), Sentinel Agent Platform

### Community 22 - "Security Evaluation Screenshot"
Cohesion: 0.32
Nodes (8): Attack Block Rate: 98.8% (82/83 blocked), Security Evaluation Dashboard (Sentinel UI), 137 labelled evaluation cases, Live mock-collector demo (proof of effect), No Middleware: 100.0% of attacks the policy would allow, Would a prohibited action get past the policy? (evaluation question), Secret-channel leak metric: 0/34 (baseline policy), Sentinel (ECS/Docker, Codex CLI Agent)

### Community 23 - "Governance & Threat Register"
Cohesion: 0.25
Nodes (8): Kill Switch Plan Threat Model, Approval Safety Design Choice, Operational Controls Coverage, Named Operational Gaps, Agent Launchpad Kill Switch Threat Model, Threat Model Review Triggers, TM-AGENT-006: Cross-Agent Evidence Leakage, TM-OPS-001: Unbounded Audit-Log Growth

### Community 24 - "Deployment & Setup Docs"
Cohesion: 0.38
Nodes (7): Project Setup Workflow, Existing Linux ECS Deployment, Deployment Secret Handling, Terraform Deployment, Rootless Podman Setup, Local POC Startup, Sentinel

### Community 25 - "Architecture Components"
Cohesion: 0.29
Nodes (7): AgentService Component, Deployment Profiles, Fastify API Component, Volc Agent Launchpad Architecture, Runtime Providers (CodexRunner / ContainerCodexRunner), JsonStore / Storage Layer, Web UI Component

### Community 26 - "Kill Switch Overview & Bypass"
Cohesion: 0.33
Nodes (7): Exfiltration Guard Implementation Plan, Defect: bash -lc Quote-Wrapping Bypass, Known Bypass: base64-encoded eval, 56-Probe Red-Team Sweep, OWASP Agentic Design Principle (Propose vs Authorize), TM-AGENT-003: Obfuscated Command Evasion, Sentinel Known Limitations

### Community 27 - "Red-Team Probe Script"
Cohesion: 0.33
Nodes (3): ctx, missed, probes

### Community 28 - "Hackathon Extension Tracks"
Cohesion: 0.33
Nodes (6): Extension Seams (Glass Box / Bouncer / Kill Switch), Bouncer Track, Glass Box Track, Kill Switch Track (Hackathon Spec), Three-Day Hackathon Plan, Kill Switch Track (Selected)

### Community 29 - "Volcengine Deployment Config"
Cohesion: 0.33
Nodes (5): deploy-volcengine.sh script, TF_VAR_app_auth_token, TF_VAR_ark_api_key, TF_VAR_ark_base_url, TF_VAR_ark_model

### Community 30 - "Security Policy Docs"
Cohesion: 0.40
Nodes (5): Pull Request Guidelines, Landlock Sandbox Fallback, Security Known Limitations, Report a Vulnerability Process, Safe Use Guidance

### Community 32 - "Prompt Injection Planting Script"
Cohesion: 0.50
Nodes (3): collectorIndex, target, [workspace]

### Community 33 - "Human Approval & Host Grant"
Cohesion: 0.67
Nodes (3): TM-AGENT-005: Consequential Egress Without Oversight, Human Approval (Held Runs), Run-Scoped Host Grant

## Knowledge Gaps
- **236 isolated node(s):** `name`, `version`, `private`, `type`, `main` (+231 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **10 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `redactCommand()` connect `Command Policy & Tests` to `AgentService Test Suite`, `Governance & Threat Register`?**
  _High betweenness centrality (0.050) - this node is a cross-community bridge._
- **Why does `Named Operational Gaps` connect `Governance & Threat Register` to `Command Policy & Tests`?**
  _High betweenness centrality (0.049) - this node is a cross-community bridge._
- **Why does `Sentinel` connect `Deployment & Setup Docs` to `Policy Evaluation Defects`, `Governance & Threat Register`, `Architecture Components`, `Kill Switch Overview & Bypass`, `Hackathon Extension Tracks`, `Security Policy Docs`?**
  _High betweenness centrality (0.046) - this node is a cross-community bridge._
- **Are the 15 inferred relationships involving `createApp()` (e.g. with `.createAgent()` and `.deleteAgent()`) actually correct?**
  _`createApp()` has 15 INFERRED edges - model-reasoned connections that need verification._
- **What connects `name`, `version`, `private` to the rest of the system?**
  _236 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `AgentService Core Module` be split into smaller, more focused modules?**
  _Cohesion score 0.08184143222506395 - nodes in this community are weakly interconnected._
- **Should `AgentService Test Suite` be split into smaller, more focused modules?**
  _Cohesion score 0.06944444444444445 - nodes in this community are weakly interconnected._