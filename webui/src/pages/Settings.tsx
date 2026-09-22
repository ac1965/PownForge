import { FormEvent, useEffect, useState } from "react";
import { api, AppSettings, Language } from "../api/client";

export default function Settings() {
  const [model, setModel] = useState("");
  const [language, setLanguage] = useState<Language>("ja");
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api
      .getSettings()
      .then((s) => {
        setModel(s.model ?? "");
        setLanguage(s.language);
        setLoaded(true);
      })
      .catch((e) => setError(String(e)));
  }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setSaved(false);
    const body: AppSettings = { model: model.trim() || null, language };
    api
      .updateSettings(body)
      .then(() => setSaved(true))
      .catch((e) => setError(String(e)))
      .finally(() => setSaving(false));
  };

  return (
    <div>
      <h2>Settings</h2>
      <p className="muted">
        analyze/walkthroughが使うAIモデルと出力言語の既定値です。各画面のmodel欄を空にすると、ここで保存した値が使われます。
      </p>
      {error && <p className="error">{error}</p>}
      {saved && <p className="muted">保存しました。</p>}

      {loaded && (
        <form onSubmit={submit} className="form-grid">
          <label>
            model(任意、llmルーターに渡すモデル名)
            <input
              value={model}
              onChange={(e) => {
                setModel(e.target.value);
                setSaved(false);
              }}
              placeholder="qwen3:14b / claude-haiku-4.5 / gpt-4o-mini"
            />
          </label>
          <p className="muted">
            例: ローカルOllamaなら <code>qwen3:14b</code>。Claude
            Consoleを使うには <code>llm install llm-anthropic</code> と{" "}
            <code>llm keys set anthropic</code>{" "}
            (APIキー入力はターミナルで行ってください)を実行した上で{" "}
            <code>claude-haiku-4.5</code> 等を指定します。空にすると
            <code>llm</code> CLI自身のデフォルトモデルが使われます。
          </p>
          <label>
            language(analyze/walkthroughの出力言語)
            <select
              value={language}
              onChange={(e) => {
                setLanguage(e.target.value as Language);
                setSaved(false);
              }}
            >
              <option value="ja">日本語</option>
              <option value="en">English</option>
            </select>
          </label>
          <button type="submit" disabled={saving}>
            {saving ? "保存中..." : "保存"}
          </button>
        </form>
      )}
    </div>
  );
}
