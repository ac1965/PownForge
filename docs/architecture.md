# アーキテクチャ

PownForge は、CLI・スコープ検証・プラグイン実行・証跡保存・レポート/分析を明確に分離します。

```text
CLI (Typer)
  │
  ├── ScopePolicy    … 対象の登録・スコープ検証（config/targets.yaml）
  ├── PluginRegistry … 利用可能なプラグインの登録・取得
  ├── ScanRunner     … ポリシー確認 → プラグインのbuild_command実行(subprocess) → normalize → 証跡保存
  ├── LabManager     … 隔離Dockerネットワーク上での攻撃対象コンテナの起動・削除・一覧
  ├── EvidenceStore  … 実行結果（JSON）の保存・読み出し
  ├── reporting      … Markdownレポート生成
  └── ai.OllamaAdapter … ローカルLLM（~/.local/bin/llm 経由）による分析
```

## 設計原則

- **AIに直接スキャンを任せない**: `ai/` はすでに保存された結果を要約・分析するだけで、
  スキャン対象や実行コマンドを決定する権限を持ちません。
- **AI推定は確定した脆弱性として扱わない**: `pownforge analyze` がLLMの応答から
  生成する`Finding`は常に`source="ai"`を持ち、レポート上でも「AI推定・要確認」と
  明記されます。`severity`はLLMの自由記述ではなく固定のenum(`info/low/medium/
  high/critical`)で検証し、想定外の値は`info`にフォールバックしてタイトル・詳細は
  保持します（1件の逸脱で応答全体を捨てない）。
- **スコープはコードで強制する**: `pownforge scan` は `config/targets.yaml` に
  登録された対象名でしか実行できません。任意のホスト名・URLを直接引数に取りません。
  `pownforge lab add` も最終的に同じ `ScopePolicy.add_target()` を通ります。
- **コマンド組み立てと実行を分離する**: プラグインは `build_command`/`normalize` の
  みを担当し、実際に外部プロセスを起動するのは `ScanRunner`（`LabManager` も同様の
  分離）に一本化しています。証跡の保存形式やファイルパスは `evidence/` が一元管理し、
  プラグインが独自形式で永続化することはありません（中間出力を一時ファイルに書いても
  `normalize` 内で読み込み次第削除します）。

## プラグインインターフェース

`src/pownforge/plugins/base.py` の `Plugin` 抽象クラスを実装します。

- `check() -> bool`: 必要な外部ツールが利用可能か
- `build_command(target, options) -> list[str]`: 実行するコマンド（検証済みtargetのみを使用）
- `normalize(target, raw_stdout, raw_stderr) -> dict`: 生出力をJSON化可能な形式に変換
  （`NetworkPlugin`/`WebPlugin` は現在、nmapのXML/ffufのJSON出力を構造化データに
  変換済み。詳細は [docs/walkthrough.md](walkthrough.md) の実機検証を参照）
- `version_command() -> list[str] | None`: ツールのバージョン確認コマンド
  （省略可、既定は`None`）。`build_command`と同様にargvを返すだけで、
  実行するのは`ScanRunner`。返した場合は`Evidence.tool_version`に記録される
- `parse_version_output(stdout, stderr) -> str | None`: `version_command()`の
  出力から実際のバージョン文字列を取り出す（既定は「stdoutの最初の行、無ければ
  stderrの最初の行」）。ツールが警告等を同じストリームに先に出す場合は
  オーバーライドする（`NucleiPlugin`はGoランタイムの警告行を読み飛ばして
  `Nuclei Engine Version: ...`の行を探す）

`normalize()`が返す辞書に`"_findings"`キー（`{"title", "severity", "detail"}`の
リスト）を含めると、`ScanRunner`がそれを取り出して`Finding`（`source="tool"`）に
変換し`RunRecord.findings`へ格納します（`NucleiPlugin`/`KubernetesPlugin`が使用）。
このキーを使わないプラグイン（`NetworkPlugin`/`WebPlugin`）には影響しません。ツール側の
severity表記が`Severity` enumに合わない場合は`info`にフォールバックし、
finding自体は破棄しません（`core/finding_utils.py::coerce_finding`、
`pownforge analyze`のJSON解析と共通のロジックを使っています）。

## 今後の拡張

- Target modelの`type`/`environment`拡張（web/api/k8s/実案件の区別が必要になった時点で）
- Emacs連携（`pownforge.el`）
