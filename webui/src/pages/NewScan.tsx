import { FormEvent, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, PluginInfo, Target } from "../api/client";

interface OptionRow {
  key: string;
  value: string;
}

export default function NewScan() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [targets, setTargets] = useState<Target[]>([]);
  const [plugins, setPlugins] = useState<PluginInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [targetName, setTargetName] = useState(searchParams.get("target") ?? "");
  const [pluginName, setPluginName] = useState("");
  const [options, setOptions] = useState<OptionRow[]>([{ key: "", value: "" }]);

  useEffect(() => {
    Promise.all([api.listTargets(), api.listPlugins()])
      .then(([t, p]) => {
        setTargets(t);
        setPlugins(p);
      })
      .catch((e) => setError(String(e)));
  }, []);

  const selectedTarget = targets.find((t) => t.name === targetName);
  const availablePlugins =
    selectedTarget && selectedTarget.allowed_plugins.length > 0
      ? plugins.filter((p) => selectedTarget.allowed_plugins.includes(p.name))
      : plugins;

  const selectedPlugin = plugins.find((p) => p.name === pluginName);

  const updateOption = (index: number, field: "key" | "value", value: string) => {
    setOptions((prev) => prev.map((row, i) => (i === index ? { ...row, [field]: value } : row)));
  };

  const addOptionRow = () => setOptions((prev) => [...prev, { key: "", value: "" }]);
  const removeOptionRow = (index: number) =>
    setOptions((prev) => prev.filter((_, i) => i !== index));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!targetName || !pluginName) return;
    setSubmitting(true);
    setError(null);
    const optionsMap = Object.fromEntries(
      options.filter((row) => row.key.trim()).map((row) => [row.key.trim(), row.value]),
    );
    api
      .createScan(targetName, pluginName, optionsMap)
      .then((created) => navigate(`/scans/${created.job_id}/live`))
      .catch((e) => setError(String(e)))
      .finally(() => setSubmitting(false));
  };

  return (
    <div>
      <h2>New Scan</h2>
      {error && <p className="error">{error}</p>}
      {targets.length === 0 && (
        <p className="muted">
          登録済みの対象がありません。先に <a href="/targets">Targets</a> ページで対象を登録してください。
        </p>
      )}
      <form onSubmit={submit} className="form-grid">
        <label>
          target
          <select required value={targetName} onChange={(e) => setTargetName(e.target.value)}>
            <option value="" disabled>
              選択してください
            </option>
            {targets.map((t) => (
              <option key={t.name} value={t.name}>
                {t.name} ({t.address})
              </option>
            ))}
          </select>
        </label>
        <label>
          plugin
          <select required value={pluginName} onChange={(e) => setPluginName(e.target.value)}>
            <option value="" disabled>
              選択してください
            </option>
            {availablePlugins.map((p) => {
              const kindMismatch =
                !!selectedTarget && !!p.expected_kind && p.expected_kind !== selectedTarget.kind;
              return (
                <option key={p.name} value={p.name} disabled={!p.tool_available || kindMismatch}>
                  {p.name}
                  {!p.tool_available ? `（${p.required_tool} が見つかりません）` : ""}
                  {p.tool_available && kindMismatch ? `（--kind ${p.expected_kind} の対象が必要）` : ""}
                </option>
              );
            })}
          </select>
        </label>

        <div>
          <p>options</p>
          {selectedPlugin?.options && selectedPlugin.options.length > 0 && (
            <ul className="muted">
              {selectedPlugin.options.map((o) => (
                <li key={o.name}>
                  <code>{o.name}</code>
                  {o.required ? "（必須）" : ""}: {o.description}
                  {o.default !== null ? ` 既定: ${o.default}` : ""}
                  {o.choices ? ` 候補: ${o.choices.join(" | ")}` : ""}
                </li>
              ))}
            </ul>
          )}
          {selectedPlugin?.options?.length === 0 && <p className="muted">このプラグインにoptionはありません。</p>}
          {options.map((row, i) => (
            <div key={i} className="option-row">
              <input
                placeholder="key（例: ports, wordlist）"
                value={row.key}
                onChange={(e) => updateOption(i, "key", e.target.value)}
              />
              <input
                placeholder="value"
                value={row.value}
                onChange={(e) => updateOption(i, "value", e.target.value)}
              />
              <button type="button" onClick={() => removeOptionRow(i)}>
                削除
              </button>
            </div>
          ))}
          <button type="button" onClick={addOptionRow}>
            + option行を追加
          </button>
        </div>

        <button type="submit" disabled={submitting || !targetName || !pluginName}>
          {submitting ? "開始中..." : "スキャン開始"}
        </button>
      </form>
    </div>
  );
}
