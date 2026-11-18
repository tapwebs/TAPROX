import { useState } from "react";
import { RequestError } from "@/components/RequestError";
import { Button } from "@/components/ui/Button";
import { DefinitionList } from "@/components/ui/DefinitionList";
import { SelectField, TextField } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { StateView } from "@/components/ui/StateView";
import { Table, Td, Th } from "@/components/ui/Table";
import { ApiError } from "@/lib/api/client";
import type { AnnotationIn } from "@/lib/api/types";
import { useReadyBackend } from "@/lib/connection/BackendProvider";
import { useRequest } from "@/lib/useRequest";
import { Footnote, RISK_NOTE, RiskScore, parseId } from "./common";

const ROLES: readonly AnnotationIn["role"][] = ["unspecified", "gateway", "dns_server", "server", "printer", "iot", "workstation"] as const;
const TRUSTS: readonly AnnotationIn["trust"][] = ["unreviewed", "known", "ignored"] as const;

export function RiskPage({ param }: { param: string | null }) {
  const { client } = useReadyBackend();
  const id = parseId(param);
  const device = useRequest((s) => (id === null ? Promise.resolve(null) : client.getDevice(id, s)), [client, id]);
  const risk = useRequest(
    async (s) => {
      if (id === null) return null;
      try {
        return await client.getDeviceRisk(id, s);
      } catch (cause) {
        if (cause instanceof ApiError && cause.status === 404) return null; // a device with no counted alerts
        throw cause;
      }
    },
    [client, id],
  );
  const [role, setRole] = useState<AnnotationIn["role"] | null>(null);
  const [trust, setTrust] = useState<AnnotationIn["trust"] | null>(null);
  const [note, setNote] = useState("");
  const [saved, setSaved] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  if (id === null) return <StateView variant="error" title="This is not a valid device number" description="Open a device from the inventory." />;
  if (device.isLoading || risk.isLoading) return <StateView variant="loading" title="Loading device risk" />;
  if (!device.data) return device.error ? <RequestError error={device.error} what="the device" onRetry={device.reload} /> : null;
  const d = device.data;
  const r = risk.data;
  const currentRole = role ?? r?.role ?? "unspecified";
  const currentTrust = trust ?? r?.trust ?? "unreviewed";

  const save = async () => {
    setProblem(null);
    setSaved(false);
    try {
      await client.putAnnotation(id, { role: currentRole, trust: currentTrust, note: note.trim() || null });
      setSaved(true);
      risk.reload();
    } catch (cause) {
      setProblem(cause instanceof ApiError ? cause.message : "The annotation could not be saved.");
    }
  };

  return (
    <div className="grid gap-4">
      <a href={`#/devices/${String(id)}`} className="text-sm text-link underline underline-offset-2">Back to the device</a>
      <Panel title={`Risk profile: ${d.observed.hostname ?? d.observed.ip ?? d.mac}`} description="A device's score combines its counted alerts; older alerts weigh less.">
        <DefinitionList
          items={[
            { label: "Address", value: d.observed.ip ?? "unknown", mono: true },
            { label: "Hardware address", value: d.mac, mono: true },
            { label: "Risk", value: r ? <RiskScore value={r.score} /> : "No alerts are counted for this device" },
            ...(r ? [{ label: "Weight halves after", value: `${String(r.half_life_days)} days` }] : []),
          ]}
        />
        <Footnote>{RISK_NOTE}</Footnote>
        <p className="mt-2 text-sm">
          <a className="text-link underline underline-offset-2" href={`#/alerts?device=${String(id)}`}>All alerts of this device</a>
          {" · "}
          <a className="text-link underline underline-offset-2" href={`#/topology`}>Network topology</a>
        </p>
      </Panel>

      <Panel title="Alerts that count" description="Alerts marked false positive or suppressed count as zero.">
        {r && r.contributing.length > 0 ? (
          <Table label="Contributing alerts">
            <thead><tr><Th>Alert</Th><Th>Rule</Th><Th>Status</Th><Th>Risk</Th><Th>Weight now</Th></tr></thead>
            <tbody>
              {r.contributing.map((c) => (
                <tr key={c.alert_id}>
                  <Td><a className="text-link underline underline-offset-2" href={`#/alerts/${String(c.alert_id)}`}>{c.title}</a></Td>
                  <Td mono>{c.rule_id}</Td>
                  <Td>{c.status}</Td>
                  <Td><RiskScore value={c.risk} /></Td>
                  <Td mono>{Math.round(c.decay * 100)}%</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <p className="text-sm text-fg-muted">No alerts from the sessions analysed are attached to this device.</p>
        )}
      </Panel>

      <Panel title="What you know about this device" description="Your own statement. It lowers the weight of alerts about a device you mark as known; it is not discovered.">
        <div className="grid gap-3 md:grid-cols-3">
          <SelectField label="Role" value={currentRole} onChange={(e) => { setRole(e.target.value as AnnotationIn["role"]); }}>
            {ROLES.map((x) => (<option key={x} value={x}>{x.replace("_", " ")}</option>))}
          </SelectField>
          <SelectField label="Trust" value={currentTrust} onChange={(e) => { setTrust(e.target.value as AnnotationIn["trust"]); }}>
            {TRUSTS.map((x) => (<option key={x} value={x}>{x}</option>))}
          </SelectField>
          <TextField label="Note" value={note} maxLength={300} onChange={(e) => { setNote(e.target.value); }} />
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Button variant="primary" onClick={() => { void save(); }}>Save</Button>
          <div role="status" className="text-sm text-fg-muted">{saved ? "Saved." : ""}</div>
        </div>
        {problem && <p role="alert" className="mt-2 text-sm text-critical">{problem}</p>}
      </Panel>
    </div>
  );
}
