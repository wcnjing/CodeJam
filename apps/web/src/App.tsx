import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, setAuthToken } from "./api";
import type {
  Agent,
  AgentRun,
  ApprovalRequest,
  EvaluationSummary,
  Message,
  PolicyDecision,
  Principal,
  SystemInfo,
} from "./types";
import { AuditTimeline } from "./components/AuditTimeline";
import { DecisionExplanation } from "./components/DecisionExplanation";
import type { PolicyMode } from "./lib/ruleExplanations";
import { PendingApprovalCard, ResolvedApprovalCard } from "./components/ApprovalCard";
import { RecoveryBanner } from "./components/RecoveryBanner";
import { WelcomePage } from "./components/WelcomePage";
import { ExamplePrompts } from "./components/ExamplePrompts";
import { TourBar } from "./components/TourBar";
import { buildAuditTimeline } from "./lib/timeline";
import { buildTourSteps } from "./lib/evaluationTour";

const emptyForm = {
  name: "",
  description: "",
  instructions:
    "Help me build and test software in this workspace. Keep changes small and explain the result.",
};

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function StatusPill({ status }: { status: Agent["status"] }) {
  return (
    <span className={"status status-" + status}>
      <span className="status-dot" />
      {status}
    </span>
  );
}

function Spinner() {
  return <span className="spinner" aria-label="Loading" />;
}

const pct = (value: number) => (value * 100).toFixed(1) + "%";

function EvaluationView({
  summary,
  onReload,
}: {
  summary: EvaluationSummary | null;
  onReload: () => void;
}) {
  const [tourStep, setTourStep] = useState<number | null>(null);
  const steps = useMemo(() => (summary ? buildTourSteps(summary) : []), [summary]);

  if (!summary) {
    return (
      <div className="eval-loading">
        <Spinner /> Measuring the live policy engine…
      </div>
    );
  }
  const h = summary.headline;
  const touring = tourStep !== null;
  const currentTarget = touring ? steps[tourStep!].target : null;
  const targetClass = (id: string) =>
    "eval-tour-target " + (currentTarget === id ? "tour-highlight" : "");

  return (
    <div className={"eval " + (touring ? "tour-active" : "")}>
      <header className="eval-header">
        <div>
          <span className="eyebrow">Security Evaluation</span>
          <h1>Would a prohibited action get past the policy?</h1>
          <p>
            The policy <em>decision</em> over {summary.corpusSize} labelled cases, computed live
            from the running engine — an attack "escapes" when the policy would allow it, at
            which point its effect could occur. That a byte physically never leaves is proven
            separately by the live mock-collector demo (zero requests). This is not observed
            execution.
          </p>
        </div>
        <div className="eval-header-actions">
          <button className="button button-ghost" onClick={() => setTourStep(0)}>
            ⌁ Guide me through this
          </button>
          <button className="button button-ghost" onClick={onReload}>
            ↻ Re-measure
          </button>
        </div>
      </header>

      {touring && (
        <TourBar
          step={steps[tourStep!]}
          index={tourStep!}
          total={steps.length}
          onPrev={() => setTourStep((value) => Math.max(0, (value ?? 0) - 1))}
          onNext={() =>
            setTourStep((value) => {
              const next = (value ?? 0) + 1;
              return next >= steps.length ? null : next;
            })
          }
          onExit={() => setTourStep(null)}
        />
      )}

      {/* Baseline vs protected: the policy-predicted escape rate. */}
      <section className={"eval-hero " + targetClass("hero")}>
        <div className="eval-hero-side baseline">
          <span className="eval-hero-label">No middleware</span>
          <span className="eval-hero-value">{pct(h.baselineEscapeRate)}</span>
          <span className="eval-hero-sub">of attacks the policy would allow</span>
        </div>
        <div className="eval-hero-arrow">→</div>
        <div className="eval-hero-side protected">
          <span className="eval-hero-label">Sentinel</span>
          <span className="eval-hero-value">{pct(h.unsafeActionEscapeRate)}</span>
          <span className="eval-hero-sub">Policy-predicted escape rate</span>
        </div>
      </section>

      <section className="eval-tiles">
        <div className={"eval-tile " + targetClass("tile-attacks")}>
          <span className="eval-tile-value">{pct(h.attackBlockRate)}</span>
          <span className="eval-tile-label">Attack block rate</span>
          <span className="eval-tile-sub">{h.attacks - h.escaped}/{h.attacks} blocked</span>
        </div>
        <div className={"eval-tile good " + targetClass("tile-secrets")}>
          <span className="eval-tile-value">
            {summary.secrets.leaks}/{summary.secrets.attacks}
          </span>
          <span className="eval-tile-label">Secret-channel attacks allowed</span>
          <span className="eval-tile-sub">
            baseline policy allowed {summary.secrets.baselineLeaks}/{summary.secrets.attacks}
          </span>
        </div>
        <div className={"eval-tile " + targetClass("tile-fp")}>
          <span className="eval-tile-value">{pct(summary.falsePositiveRate)}</span>
          <span className="eval-tile-label">False positives</span>
          <span className="eval-tile-sub">on {summary.benign} legitimate tasks</span>
        </div>
        <div className={"eval-tile " + targetClass("tile-latency")}>
          <span className="eval-tile-value">{summary.latency.p95.toFixed(1)} µs</span>
          <span className="eval-tile-label">Policy latency p95</span>
          <span className="eval-tile-sub">p50 {summary.latency.p50.toFixed(1)} µs</span>
        </div>
      </section>

      <section className="eval-columns">
        <div className={"eval-panel " + targetClass("family")}>
          <span className="eyebrow">Coverage by attack family</span>
          <ul className="eval-family">
            {summary.families.map((f) => {
              const blocked = f.attacks - f.escaped;
              const rate = f.attacks === 0 ? 1 : blocked / f.attacks;
              return (
                <li key={f.family}>
                  <span className={"eval-family-mark " + (f.escaped === 0 ? "ok" : "gap")}>
                    {f.escaped === 0 ? "✓" : "✗"}
                  </span>
                  <span className="eval-family-name">{f.family}</span>
                  <span className="eval-family-bar">
                    <span
                      className={"eval-family-fill " + (f.escaped === 0 ? "ok" : "gap")}
                      style={{ width: pct(rate) }}
                    />
                  </span>
                  <span className="eval-family-count">
                    {blocked}/{f.attacks}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>

        <div className={"eval-panel " + targetClass("classifier")}>
          <span className="eyebrow">Classifier quality (reviewer challenge set)</span>
          <ul className="eval-metrics">
            <li>
              <span>Core detection</span>
              <strong>{pct(summary.policy.coreRecall)}</strong>
            </li>
            <li>
              <span>Evasion resistance</span>
              <strong>{pct(summary.policy.evasionRecall)}</strong>
            </li>
            <li>
              <span>
                External-review recall
                <em className="eval-metric-note">
                  {summary.policy.externalReviewAttacks} attacks written without
                  reading the rules
                </em>
              </span>
              <strong>{pct(summary.policy.externalReviewRecall)}</strong>
            </li>
            <li>
              <span>
                External-review false positives
                <em className="eval-metric-note">
                  {summary.policy.externalReviewBenign} legitimate reviewer cases
                </em>
              </span>
              <strong>{pct(summary.policy.externalReviewFalsePositiveRate)}</strong>
            </li>
            <li>
              <span>
                Internal red-team regressions
                <em className="eval-metric-note">
                  authored while reading the rules; retained, not independent
                </em>
              </span>
              <strong>{summary.policy.internalRedTeam}</strong>
            </li>
            <li>
              <span>Precision</span>
              <strong>{pct(summary.policy.precision)}</strong>
            </li>
            <li>
              <span>F1</span>
              <strong>{pct(summary.policy.f1)}</strong>
            </li>
          </ul>
          {summary.escapes.length > 0 && (
            <div className="eval-escapes">
              <span className="eyebrow">Known residual (named, not hidden)</span>
              {summary.escapes.map((e) => (
                <code key={e.id}>
                  {e.id} · {e.family}
                </code>
              ))}
            </div>
          )}
        </div>
      </section>

      <section className={"eval-loop " + targetClass("loop")}>
        <span className="eyebrow">The governance loop — every command, not every prompt</span>
        <div className="eval-loop-row">
          {["Intercept", "Decide", "Contain / Hold", "Approve", "Recover"].map((step, i) => (
            <span className="eval-loop-step" key={step}>
              {step}
              {i < 4 && <span className="eval-loop-arrow">→</span>}
            </span>
          ))}
        </div>
      </section>
    </div>
  );
}

export default function App() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [system, setSystem] = useState<SystemInfo | null>(null);
  // What this deployment does with a denial. Every "held" / "blocked" label in
  // the UI is derived from this rather than written into the copy, so a
  // deployment in monitor mode or with a narrowed POLICY_REVIEW_RULES is
  // described accurately instead of aspirationally.
  const policyMode: PolicyMode | null = system
    ? { enforcement: system.policyEnforcement, reviewRules: system.policyReviewRules }
    : null;
  const [showCreate, setShowCreate] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [prompt, setPrompt] = useState("");
  const [activeRun, setActiveRun] = useState<AgentRun | null>(null);
  const [runs, setRuns] = useState<AgentRun[]>([]);
  const [policyEvents, setPolicyEvents] = useState<PolicyDecision[]>([]);
  const [showPolicy, setShowPolicy] = useState(false);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [approvalReason, setApprovalReason] = useState("");
  const [view, setView] = useState<"welcome" | "agents" | "evaluation">("welcome");
  const [evaluation, setEvaluation] = useState<EvaluationSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authInput, setAuthInput] = useState("");
  const messageEnd = useRef<HTMLDivElement>(null);
  const selectedIdRef = useRef<string | null>(null);
  const mountedRef = useRef(true);
  const pollingRunIds = useRef(new Set<string>());
  selectedIdRef.current = selectedId;

  const pendingApproval = useMemo(
    () =>
      approvals.find(
        (item) => item.runId === activeRun?.id && item.status === "pending",
      ) ?? null,
    [approvals, activeRun],
  );

  const resolvedApproval = useMemo(
    () =>
      approvals.find(
        (item) => item.runId === activeRun?.id && item.status !== "pending",
      ) ?? null,
    [approvals, activeRun],
  );

  const blockedDecision = useMemo(
    () => policyEvents.find((event) => event.runId === activeRun?.id) ?? null,
    [policyEvents, activeRun],
  );

  const budgetDecision = useMemo(
    () =>
      policyEvents.find(
        (event) => event.runId === activeRun?.id && event.rule === "step-budget-exceeded",
      ) ?? null,
    [policyEvents, activeRun],
  );

  const timelineEvents = useMemo(
    () => buildAuditTimeline(runs, policyEvents, approvals),
    [runs, policyEvents, approvals],
  );

  const selected = useMemo(
    () => agents.find((agent) => agent.id === selectedId) ?? null,
    [agents, selectedId],
  );

  const refreshAgents = useCallback(async () => {
    const { agents: next } = await api.listAgents();
    setAgents(next);
    setSelectedId((current) =>
      current && next.some((agent) => agent.id === current)
        ? current
        : (next[0]?.id ?? null),
    );
    return next;
  }, []);

  const refreshMessages = useCallback(async (agentId: string) => {
    const result = await api.messages(agentId);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setMessages(result.messages);
    }
  }, []);

  const refreshPolicyEvents = useCallback(async (agentId: string) => {
    const result = await api.policyEvents(agentId);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setPolicyEvents(result.policyEvents);
    }
  }, []);

  const refreshApprovals = useCallback(async (agentId: string) => {
    const result = await api.approvals(agentId);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setApprovals(result.approvals);
    }
  }, []);

  const refreshRuns = useCallback(async (agentId: string) => {
    const result = await api.runs(agentId);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setRuns(result.runs);
    }
    return result.runs;
  }, []);

  const openEvaluation = useCallback(async () => {
    setView("evaluation");
    setError(null);
    try {
      setEvaluation(await api.evaluation());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  }, []);

  const openPlayground = useCallback(async () => {
    setView("agents");
    const current = await refreshAgents().catch(() => agents);
    if (current.length === 0) {
      setForm(emptyForm);
      setShowCreate(true);
    }
  }, [agents, refreshAgents]);

  const bootstrap = useCallback(async () => {
    await Promise.all([
      refreshAgents(),
      api.system().then(setSystem),
      api.me().then(({ principal: current }) => setPrincipal(current)),
    ]);
  }, [refreshAgents]);

  useEffect(() => {
    mountedRef.current = true;
    void api
      .auth()
      .then(async ({ required }) => {
        if (!mountedRef.current) return;
        setAuthRequired(required);
        if (!required) await bootstrap();
        // Deep-link: #evaluation opens the Security Evaluation dashboard directly.
        if (!required && window.location.hash === "#evaluation") {
          void openEvaluation();
        }
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : String(reason)));
    return () => {
      mountedRef.current = false;
    };
  }, [bootstrap, openEvaluation]);

  useEffect(() => {
    setActiveRun(null);
    setRuns([]);
    setShowSettings(false);
    setShowPolicy(false);
    setPolicyEvents([]);
    setApprovals([]);
    setApprovalReason("");
    if (!selectedId) {
      setMessages([]);
      return;
    }
    void refreshPolicyEvents(selectedId).catch(() => undefined);
    void refreshApprovals(selectedId).catch(() => undefined);
    void Promise.all([refreshMessages(selectedId), refreshRuns(selectedId)])
      .then(([, fetchedRuns]) => {
        if (selectedIdRef.current !== selectedId) return;
        const latest = fetchedRuns[0] ?? null;
        setActiveRun(latest);
        if (latest && ["queued", "running"].includes(latest.status)) {
          void pollRun(latest.id, selectedId).catch((reason) =>
            setError(reason instanceof Error ? reason.message : String(reason)),
          );
        }
      })
      .catch((reason) =>
        setError(reason instanceof Error ? reason.message : String(reason)),
      );
  }, [refreshMessages, refreshPolicyEvents, refreshApprovals, refreshRuns, selectedId]);

  useEffect(() => {
    if (selected) {
      setForm({
        name: selected.name,
        description: selected.description,
        instructions: selected.instructions,
      });
    }
  }, [selected]);

  useEffect(() => {
    messageEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activeRun]);

  const createAgent = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { agent } = await api.createAgent(form);
      await refreshAgents();
      setSelectedId(agent.id);
      setShowCreate(false);
      setForm(emptyForm);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const saveAgent = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      await api.updateAgent(selected.id, form);
      await refreshAgents();
      setShowSettings(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const toggleAgent = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      if (selected.status === "stopped") {
        await api.startAgent(selected.id);
      } else {
        await api.stopAgent(selected.id);
      }
      await refreshAgents();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const deleteAgent = async () => {
    if (!selected) return;
    if (!window.confirm("Delete " + selected.name + "? Its workspace will be archived.")) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.deleteAgent(selected.id);
      await refreshAgents();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const pollRun = async (runId: string, agentId: string) => {
    if (pollingRunIds.current.has(runId)) return;
    pollingRunIds.current.add(runId);
    try {
      while (mountedRef.current) {
        await new Promise((resolve) => window.setTimeout(resolve, 900));
        if (!mountedRef.current) return;
        const result = await api.run(runId);
        if (selectedIdRef.current === agentId) setActiveRun(result.run);
        if (!["queued", "running"].includes(result.run.status)) {
          await Promise.all([
            refreshMessages(agentId),
            refreshAgents(),
            refreshPolicyEvents(agentId),
            refreshApprovals(agentId),
            refreshRuns(agentId),
          ]);
          return;
        }
      }
    } finally {
      pollingRunIds.current.delete(runId);
    }
  };

  const resolveApproval = async (
    approval: ApprovalRequest,
    decision: "approve" | "deny",
  ) => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.resolveApproval(
        approval.id,
        decision,
        approvalReason.trim(),
      );
      setApprovalReason("");
      await Promise.all([refreshApprovals(selected.id), refreshAgents(), refreshRuns(selected.id)]);
      if (result.continuationRun) {
        setActiveRun(result.continuationRun);
        void pollRun(result.continuationRun.id, selected.id).catch((reason) =>
          setError(reason instanceof Error ? reason.message : String(reason)),
        );
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const sendMessage = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected || !prompt.trim()) return;
    const content = prompt.trim();
    setPrompt("");
    setError(null);
    try {
      const result = await api.sendMessage(selected.id, content);
      if (selectedIdRef.current === selected.id) {
        setMessages((current) => [...current, result.message]);
        setActiveRun(result.run);
      }
      setAgents((current) =>
        current.map((agent) =>
          agent.id === selected.id ? { ...agent, status: "busy" } : agent,
        ),
      );
      await pollRun(result.run.id, selected.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      setActiveRun(null);
      await refreshAgents();
    }
  };

  const unlock = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setAuthToken(authInput);
    try {
      await bootstrap();
      setAuthRequired(false);
      setAuthInput("");
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        setError("The access token is not valid.");
      } else {
        setError(reason instanceof Error ? reason.message : String(reason));
      }
    } finally {
      setBusy(false);
    }
  };

  if (authRequired === null) {
    return (
      <main className="auth-screen">
        <section className="auth-card" aria-live="polite">
          <div className="brand-mark">S</div>
          <span className="eyebrow">Sentinel</span>
          <h1>Connecting to the control plane</h1>
          {error ? <div className="error-banner" role="alert">{error}</div> : <Spinner />}
        </section>
      </main>
    );
  }

  if (authRequired) {
    return (
      <main className="auth-screen">
        <form className="auth-card" onSubmit={unlock}>
          <div className="brand-mark">S</div>
          <span className="eyebrow">Sentinel</span>
          <h1>Enter your access token</h1>
          <p>
            Your personal access token, issued by the platform operator. Approvals are
            recorded under the principal it identifies.
          </p>
          {error && <div className="error-banner" role="alert">{error}</div>}
          <label>
            Access token
            <input
              autoFocus
              type="password"
              value={authInput}
              onChange={(event) => setAuthInput(event.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <button className="button button-primary" disabled={busy || !authInput.trim()}>
            {busy ? <Spinner /> : "Open Sentinel"}
          </button>
        </form>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <button className="brand brand-link" onClick={() => setView("welcome")}>
          <div className="brand-mark">S</div>
          <div>
            <strong>Sentinel</strong>
            <span>
              {system?.runtimeProvider === "container"
                ? "Local container · Codex CLI"
                : "ECS / Docker · Codex CLI"}
            </span>
          </div>
        </button>

        <button
          className={"button button-ghost eval-nav " + (view === "welcome" ? "active" : "")}
          onClick={() => setView("welcome")}
        >
          <span>⌁</span> Overview
        </button>

        <button
          className={"button button-ghost eval-nav " + (view === "evaluation" ? "active" : "")}
          onClick={openEvaluation}
        >
          <span>◈</span> Security Evaluation
        </button>
        <button
          className="button button-primary create-button"
          onClick={() => {
            setForm(emptyForm);
            setShowCreate(true);
            setView("agents");
          }}
        >
          <span>＋</span> Create Agent
        </button>

        <div className="sidebar-label">
          <span>Your Agents</span>
          <span>{agents.length}</span>
        </div>
        <nav className="agent-list">
          {agents.map((agent) => (
            <button
              className={
                "agent-card " +
                (agent.id === selectedId && view === "agents" ? "selected" : "")
              }
              key={agent.id}
              onClick={() => {
                setSelectedId(agent.id);
                setView("agents");
              }}
            >
              <div className="agent-avatar">{agent.name.slice(0, 1).toUpperCase()}</div>
              <div className="agent-card-copy">
                <strong>{agent.name}</strong>
                <span>{agent.description || "Coding Agent"}</span>
              </div>
              <span className={"mini-dot mini-" + agent.status} />
            </button>
          ))}
          {agents.length === 0 && (
            <div className="empty-sidebar">
              <span>◇</span>
              Create your first coding Agent.
            </div>
          )}
        </nav>

        <div className="runtime-card">
          <span className="eyebrow">Runtime</span>
          <strong>{system?.runtime ?? "Checking…"}</strong>
          <span>
            {system?.arkModel ?? "Ark model not configured"}
            {system?.containerEngine ? " · " + system.containerEngine : ""}
          </span>
        </div>
      </aside>

      <main className="main">
        {!system?.arkConfigured || !system?.codexAvailable ? (
          <div className="config-banner">
            <span>!</span>
            <div>
              <strong>Runtime configuration needed</strong>
              <p>
                {!system?.arkConfigured
                  ? "Set ARK_API_KEY and ARK_MODEL in .env before using the Playground."
                  : system.runtimeProvider === "container"
                    ? "The local container engine or Agent Runtime image is unavailable. Rerun npm run poc."
                    : "Codex CLI was not found. Use the Docker image or install @openai/codex."}
              </p>
            </div>
          </div>
        ) : null}

        {error && (
          <div className="error-banner" role="alert">
            <span>{error}</span>
            <button onClick={() => setError(null)}>×</button>
          </div>
        )}

        {view === "welcome" ? (
          <WelcomePage onOpenPlayground={openPlayground} onOpenEvaluation={openEvaluation} />
        ) : view === "evaluation" ? (
          <EvaluationView summary={evaluation} onReload={openEvaluation} />
        ) : selected ? (
          <>
            <header className="agent-header">
              <div>
                <div className="header-title-row">
                  <h1>{selected.name}</h1>
                  <StatusPill status={selected.status} />
                </div>
                <p>{selected.description || "A Codex coding Agent in an isolated workspace."}</p>
              </div>
              <div className="header-actions">
                <button
                  className="button button-ghost"
                  onClick={() => setShowSettings((value) => !value)}
                  disabled={busy || selected.status === "busy"}
                >
                  Settings
                </button>
                <button
                  className="button button-ghost"
                  onClick={toggleAgent}
                  disabled={busy}
                >
                  {selected.status === "stopped" ? "Start" : "Stop"}
                </button>
                <button
                  className="button button-ghost"
                  onClick={() => setShowPolicy((current) => !current)}
                  disabled={busy}
                >
                  Timeline
                  {timelineEvents.length > 0 && (
                    <span className="policy-count">{timelineEvents.length}</span>
                  )}
                </button>
                <button
                  className="button button-danger"
                  onClick={deleteAgent}
                  disabled={busy || selected.status === "busy"}
                >
                  Delete
                </button>
              </div>
            </header>

            {showPolicy && (
              <section className="settings-panel">
                <div className="settings-title">
                  <div>
                    <span className="eyebrow">Audit timeline</span>
                    <h2>Every Run outcome, decision, and approval — in order</h2>
                  </div>
                  <button type="button" onClick={() => setShowPolicy(false)}>×</button>
                </div>
                <AuditTimeline events={timelineEvents} />
              </section>
            )}

            {showSettings && (
              <form className="settings-panel" onSubmit={saveAgent}>
                <div className="settings-title">
                  <div>
                    <span className="eyebrow">Agent configuration</span>
                    <h2>Instructions and identity</h2>
                  </div>
                  <button type="button" onClick={() => setShowSettings(false)}>×</button>
                </div>
                <div className="form-grid">
                  <label>
                    Name
                    <input
                      value={form.name}
                      onChange={(event) => setForm({ ...form, name: event.target.value })}
                      required
                      maxLength={80}
                    />
                  </label>
                  <label>
                    Description
                    <input
                      value={form.description}
                      onChange={(event) =>
                        setForm({ ...form, description: event.target.value })
                      }
                      maxLength={500}
                    />
                  </label>
                </div>
                <label>
                  System instructions
                  <textarea
                    value={form.instructions}
                    onChange={(event) =>
                      setForm({ ...form, instructions: event.target.value })
                    }
                    rows={5}
                    maxLength={10_000}
                  />
                </label>
                <div className="panel-footer">
                  <code>{selected.workspacePath}</code>
                  <button className="button button-primary" disabled={busy}>
                    {busy ? <Spinner /> : "Save changes"}
                  </button>
                </div>
              </form>
            )}

            <section className="playground">
              <div className="playground-topbar">
                <div>
                  <span className="eyebrow">Playground</span>
                  <h2>Build something with your Agent</h2>
                </div>
                <div className="session-info">
                  <span className="pulse" />
                  {selected.codexThreadId ? "Session connected" : "New session"}
                </div>
              </div>

              <div className="messages">
                {messages.length === 0 && !activeRun ? (
                  <div className="welcome">
                    <div className="welcome-orbit">
                      <div>⌁</div>
                    </div>
                    <h3>What should {selected.name} build?</h3>
                    <p>
                      The Agent can inspect files, write code, run commands, and continue the
                      same Codex session across messages. Here's what happens with three kinds
                      of requests:
                    </p>
                    <ExamplePrompts onPick={setPrompt} mode={policyMode} />
                  </div>
                ) : (
                  messages.map((message) => (
                    <article className={"message message-" + message.role} key={message.id}>
                      <div className="message-meta">
                        <strong>{message.role === "user" ? "You" : selected.name}</strong>
                        <span>{formatTime(message.createdAt)}</span>
                      </div>
                      <div className="message-body">{message.content}</div>
                    </article>
                  ))
                )}
                {activeRun && ["queued", "running"].includes(activeRun.status) && (
                  <article className="message message-assistant thinking">
                    <div className="message-meta">
                      <strong>{selected.name}</strong>
                      <span>working in the Agent workspace</span>
                    </div>
                    <div className="thinking-row">
                      <Spinner />
                      Codex is reading, editing, or running commands…
                    </div>
                  </article>
                )}
                {activeRun?.status === "failed" && (
                  <article className="run-error">
                    <strong>Run failed</strong>
                    <span>{activeRun.error}</span>
                  </article>
                )}
                {activeRun?.status === "terminated" && (
                  <>
                    <article className="run-blocked" role="alert">
                      <strong>Run terminated by resource budget</strong>
                      <span>
                        {activeRun.error ??
                          "The Run exceeded its step budget and was stopped by the platform."}
                      </span>
                      {budgetDecision && (
                        <DecisionExplanation
                          rule={budgetDecision.rule}
                          command={budgetDecision.command}
                          detail={budgetDecision.detail}
                          mode={policyMode}
                        />
                      )}
                    </article>
                    <RecoveryBanner cause="terminated" workspacePath={selected.workspacePath} />
                  </>
                )}
                {activeRun?.status === "held" && !pendingApproval && resolvedApproval && (
                  <>
                    <ResolvedApprovalCard approval={resolvedApproval} />
                    {resolvedApproval.status === "denied" && (
                      <RecoveryBanner cause="denied" workspacePath={selected.workspacePath} />
                    )}
                  </>
                )}
                {activeRun?.status === "held" && pendingApproval && (
                  <PendingApprovalCard
                    mode={policyMode}
                    approval={pendingApproval}
                    principal={principal}
                    reason={approvalReason}
                    onReasonChange={setApprovalReason}
                    busy={busy}
                    onResolve={(decision) => resolveApproval(pendingApproval, decision)}
                  />
                )}
                {activeRun?.status === "blocked" && (
                  <>
                    <article className="run-blocked" role="alert">
                      <strong>Run blocked by command policy</strong>
                      <span>
                        The Agent attempted an action the platform denies. Its Runtime
                        container was terminated; any partial effect of the command
                        already in flight may have occurred, and all further commands
                        and retries are stopped.
                      </span>
                      {blockedDecision && (
                        <DecisionExplanation
                          rule={blockedDecision.rule}
                          command={blockedDecision.command}
                          detail={blockedDecision.detail}
                          mode={policyMode}
                        />
                      )}
                    </article>
                    <RecoveryBanner cause="blocked" workspacePath={selected.workspacePath} />
                  </>
                )}
                <div ref={messageEnd} />
              </div>

              <form className="composer" onSubmit={sendMessage}>
                <textarea
                  value={prompt}
                  onChange={(event) => setPrompt(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      event.currentTarget.form?.requestSubmit();
                    }
                  }}
                  placeholder={
                    selected.status === "stopped"
                      ? "Start this Agent to continue…"
                      : "Describe what you want the Agent to do…"
                  }
                  disabled={
                    selected.status === "stopped" ||
                    selected.status === "busy" ||
                    activeRun != null && ["queued", "running"].includes(activeRun.status)
                  }
                  rows={3}
                />
                <div className="composer-footer">
                  <span>
                    Enter to send · Shift + Enter for newline · {system?.codexSandboxMode ?? "checking sandbox"}
                  </span>
                  <button
                    className="send-button"
                    disabled={
                      !prompt.trim() ||
                      selected.status === "stopped" ||
                      selected.status === "busy" ||
                      (activeRun != null && ["queued", "running"].includes(activeRun.status))
                    }
                    aria-label="Send message"
                  >
                    ↑
                  </button>
                </div>
              </form>
            </section>
          </>
        ) : (
          <div className="no-agent">
            <div className="no-agent-art">S</div>
            <span className="eyebrow">Sentinel</span>
            <h1>Your runtime is ready for an Agent.</h1>
            <p>Create a workspace, give Codex a job, and continue the conversation here.</p>
            <button
              className="button button-primary"
              onClick={() => {
                setForm(emptyForm);
                setShowCreate(true);
              }}
            >
              Create your first Agent
            </button>
          </div>
        )}
      </main>

      {showCreate && (
        <div className="modal-backdrop" onMouseDown={() => setShowCreate(false)}>
          <form
            className="modal"
            onSubmit={createAgent}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="modal-heading">
              <div>
                <span className="eyebrow">New workspace</span>
                <h2>Create an Agent</h2>
                <p>Each Agent gets a persistent folder and a resumable Codex session.</p>
              </div>
              <button type="button" onClick={() => setShowCreate(false)}>×</button>
            </div>
            <label>
              Name
              <input
                autoFocus
                placeholder="Frontend Builder"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
                maxLength={80}
              />
            </label>
            <label>
              Description
              <input
                placeholder="Builds polished React prototypes"
                value={form.description}
                onChange={(event) =>
                  setForm({ ...form, description: event.target.value })
                }
                maxLength={500}
              />
            </label>
            <label>
              Instructions
              <textarea
                value={form.instructions}
                onChange={(event) =>
                  setForm({ ...form, instructions: event.target.value })
                }
                rows={6}
                maxLength={10_000}
              />
            </label>
            <div className="modal-footer">
              <button
                type="button"
                className="button button-ghost"
                onClick={() => setShowCreate(false)}
              >
                Cancel
              </button>
              <button className="button button-primary" disabled={busy}>
                {busy ? <Spinner /> : "Create Agent"}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
