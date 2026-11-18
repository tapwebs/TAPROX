import { useState } from "react";
import { RequestError } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { CheckboxField, TextField } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { Table, Td, Th } from "@/components/ui/Table";
import { ApiError } from "@/lib/api/client";
import type { DetectionSettings, RuleConfig } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useRequest } from "@/lib/useRequest";
import { When } from "./common";

const STATE_TEXT: Record<RuleConfig["state"], string> = {
  evaluating: "Evaluating",
  disabled: "Switched off",
  not_evaluated: "Not evaluated",
};

function message(cause: unknown, fallback: string): string {
  return cause instanceof ApiError ? cause.message : fallback;
}

/** A value typed by the user, checked against the rule's own bounds before it is sent. */
function checkNumber(text: string, min: number, max: number): string | undefined {
  const value = Number(text);
  if (text.trim() === "" || !Number.isFinite(value)) return "Enter a number.";
  if (value < min || value > max) return `Use a value from ${String(min)} to ${String(max)}.`;
  return undefined;
}

function RuleCard({ rule, onChanged }: { rule: RuleConfig; onChanged: () => void }) {
  const { client } = useReadyBackend();
  const [enabled, setEnabled] = useState(rule.enabled);
  const [values, setValues] = useState<Record<string, string>>(Object.fromEntries(rule.params.map((p) => [p.name, String(p.value)])));
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const errors = Object.fromEntries(rule.params.map((p) => [p.name, checkNumber(values[p.name] ?? "", p.minimum, p.maximum)]));
  const invalid = Object.values(errors).some(Boolean);

  const run = async (action: () => Promise<RuleConfig>) => {
    setBusy(true);
    setProblem(null);
    setSaved(false);
    try {
      const next = await action();
      setEnabled(next.enabled);
      setValues(Object.fromEntries(next.params.map((p) => [p.name, String(p.value)])));
      setSaved(true);
      onChanged();
    } catch (cause) {
      setProblem(message(cause, "The rule could not be saved."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <li className="rounded-md border border-line bg-surface p-3">
      <details>
        <summary className="flex cursor-pointer flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-fg-muted">{rule.id}</span>
          <span className="text-sm font-semibold text-fg">{rule.name}</span>
          <StatusBadge tone={rule.state === "evaluating" ? "success" : rule.state === "disabled" ? "neutral" : "warning"}>{STATE_TEXT[rule.state]}</StatusBadge>
          {rule.customised && <span className="text-xs text-fg-muted">Changed from default</span>}
          {rule.requires_baseline && <span className="text-xs text-fg-muted">Needs a baseline</span>}
        </summary>
        <div className="mt-3 grid gap-3">
          <p className="text-sm text-fg">{rule.description}</p>
          {rule.reason && <p className="text-sm text-fg-muted">{rule.reason}</p>}
          <CheckboxField label="Rule is switched on" checked={enabled} onChange={(e) => { setEnabled(e.target.checked); }} description={`Default: ${rule.default_enabled ? "on" : "off"}. A change applies from the next analysed session.`} />
          {rule.params.length > 0 && (
            <div className="grid gap-3 md:grid-cols-2">
              {rule.params.map((p) => (
                <TextField
                  key={p.name}
                  label={`${p.name} (${p.unit})`}
                  inputMode="decimal"
                  value={values[p.name] ?? ""}
                  onChange={(e) => { setValues((v) => ({ ...v, [p.name]: e.target.value })); }}
                  hint={`Default ${String(p.default)}; allowed ${String(p.minimum)} to ${String(p.maximum)}.`}
                  error={errors[p.name]}
                />
              ))}
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            <Button
              variant="primary"
              loading={busy}
              disabled={invalid}
              onClick={() => { void run(() => client.putRule(rule.id, { enabled, params: Object.fromEntries(rule.params.map((p) => [p.name, Number(values[p.name])])) })); }}
            >
              Save {rule.id}
            </Button>
            <Button disabled={busy} onClick={() => { void run(() => client.resetRule(rule.id)); }}>Reset to defaults</Button>
          </div>
          <div role="status" className="text-sm text-fg-muted">{saved ? "Saved. It applies from the next analysed session." : ""}</div>
          {problem && <p role="alert" className="text-sm text-critical">{problem}</p>}
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <h3 className="text-xs font-medium text-fg-muted">Ordinary reasons for this pattern</h3>
              <ul className="list-disc pl-5 text-sm">{rule.benign_explanations.map((t) => (<li key={t}>{t}</li>))}</ul>
            </div>
            <div>
              <h3 className="text-xs font-medium text-fg-muted">What this rule cannot see</h3>
              <ul className="list-disc pl-5 text-sm">{rule.blind_spots.map((t) => (<li key={t}>{t}</li>))}</ul>
            </div>
          </div>
        </div>
      </details>
    </li>
  );
}

function SettingsPanel({ settings, onSaved }: { settings: DetectionSettings; onSaved: () => void }) {
  const { client } = useReadyBackend();
  const fields = [
    { key: "retention_alert_days", label: "Keep alerts for (days)", min: 7, max: 3650 },
    { key: "retention_alert_max", label: "Keep at most (alerts)", min: 100, max: 100000 },
    { key: "baseline_hours_min", label: "Baseline needs (hours of live capture)", min: 0, max: 720 },
    { key: "baseline_sessions_min", label: "Baseline needs (sessions)", min: 1, max: 100 },
    { key: "risk_half_life_days", label: "Alert weight halves after (days)", min: 1, max: 90 },
  ] as const;
  const [values, setValues] = useState<Record<string, string>>(Object.fromEntries(fields.map((f) => [f.key, String(settings[f.key])])));
  const [problem, setProblem] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const errors = Object.fromEntries(fields.map((f) => [f.key, checkNumber(values[f.key] ?? "", f.min, f.max)]));
  const save = async () => {
    setProblem(null);
    setSaved(false);
    try {
      await client.putDetectionSettings(Object.fromEntries(fields.map((f) => [f.key, Number(values[f.key])])));
      setSaved(true);
      onSaved();
    } catch (cause) {
      setProblem(message(cause, "The settings could not be saved."));
    }
  };
  return (
    <Panel title="Retention, baselines and scoring" description="Shared by all rules.">
      <div className="grid gap-3 md:grid-cols-3">
        {fields.map((f) => (
          <TextField key={f.key} label={f.label} inputMode="decimal" value={values[f.key] ?? ""} error={errors[f.key]}
            onChange={(e) => { setValues((v) => ({ ...v, [f.key]: e.target.value })); }} hint={`${String(f.min)} to ${String(f.max)}`} />
        ))}
      </div>
      <div className="mt-3 flex items-center gap-3">
        <Button variant="primary" disabled={Object.values(errors).some(Boolean)} onClick={() => { void save(); }}>Save settings</Button>
        <div role="status" className="text-sm text-fg-muted">{saved ? "Saved." : ""}</div>
      </div>
      {problem && <p role="alert" className="mt-2 text-sm text-critical">{problem}</p>}
    </Panel>
  );
}

export function RulesPage() {
  const { client } = useReadyBackend();
  const rules = useRequest((s) => client.getRules(s), [client]);
  const settings = useRequest((s) => client.getDetectionSettings(s), [client]);
  const suppressions = useRequest((s) => client.getSuppressions(s), [client]);
  const networks = useRequest((s) => client.getNetworks(s), [client]);
  const [problem, setProblem] = useState<string | null>(null);

  const act = async (action: () => Promise<unknown>, reload: () => void) => {
    setProblem(null);
    try {
      await action();
      reload();
    } catch (cause) {
      setProblem(message(cause, "The change could not be made."));
    }
  };

  if (rules.isLoading) return <StateView variant="loading" title="Loading detection rules" />;
  if (!rules.data) return rules.error ? <RequestError error={rules.error} what="the rules" onRetry={rules.reload} /> : null;
  const categories = [...new Set(rules.data.items.map((r) => r.category))];

  return (
    <div className="grid gap-4">
      {problem && <p role="alert" className="text-sm text-critical">{problem}</p>}
      {categories.map((category) => (
        <Panel key={category} title={`Rules: ${category}`} description="Open a rule to read what it does, change its values, or switch it on or off.">
          <ul className="grid gap-2">
            {rules.data?.items.filter((r) => r.category === category).map((r) => (
              <RuleCard key={`${r.id}-${String(r.customised)}-${String(r.enabled)}`} rule={r} onChanged={rules.reloadQuietly} />
            ))}
          </ul>
        </Panel>
      ))}
      {settings.data && <SettingsPanel settings={settings.data} onSaved={settings.reload} />}

      <Panel title="Suppressions" description="A suppressed rule still counts its findings but raises no alert for that entity.">
        {suppressions.data && suppressions.data.items.length > 0 ? (
          <Table label="Suppressions">
            <thead><tr><Th>Rule</Th><Th>About</Th><Th>Reason</Th><Th>Created</Th><Th>Action</Th></tr></thead>
            <tbody>
              {suppressions.data.items.map((s) => (
                <tr key={s.id}>
                  <Td mono>{s.rule_id}</Td>
                  <Td mono>{s.entity_key}</Td>
                  <Td>{s.reason}</Td>
                  <Td><When iso={s.created_at} /></Td>
                  <Td><Button onClick={() => { void act(() => client.deleteSuppression(s.id), suppressions.reload); }} aria-label={`Remove suppression of ${s.rule_id} for ${s.entity_key}`}>Remove</Button></Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <p className="text-sm text-fg-muted">No suppressions. Suppress a rule for an entity from the alert's page.</p>
        )}
      </Panel>

      <Panel title="Networks and baselines" description="Baseline rules judge a device only against what it did on the same network in earlier live sessions.">
        {networks.data && networks.data.items.length > 0 ? (
          <Table label="Networks">
            <thead><tr><Th>Network</Th><Th>Gateway</Th><Th>Live time</Th><Th>Sessions</Th><Th>Baseline</Th><Th>Action</Th></tr></thead>
            <tbody>
              {networks.data.items.map((n) => (
                <tr key={n.id}>
                  <Td mono>{n.cidr}</Td>
                  <Td mono>{n.gateway_ip ?? "unknown"}</Td>
                  <Td mono>{(n.live_seconds / 3600).toFixed(1)} of {String(n.hours_needed)} h</Td>
                  <Td mono>{n.sessions} of {n.sessions_needed}</Td>
                  <Td>{n.baseline_ready ? `Ready (${String(n.baseline_devices)} devices)` : "Still learning"}</Td>
                  <Td><Button onClick={() => { void act(() => client.resetBaseline(n.id), networks.reload); }} aria-label={`Reset what was learned for ${n.cidr}`}>Reset learning</Button></Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <p className="text-sm text-fg-muted">No live session has been analysed on a network yet, so nothing has been learned.</p>
        )}
      </Panel>
    </div>
  );
}
