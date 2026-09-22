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
  `Target.environment`が`production`の対象は`notes`(認可/契約の参照)が
  必須で、無い場合`ScopePolicy.add_target()`自体が`PolicyError`を送出します
  (CLI/Web API/Web UIいずれの登録経路でも同じチェックを通る)。
- **証跡に含まれるコマンドは秘匿情報らしき値をマスクする**: `ScanRunner`は
  実際の実行(`subprocess.Popen`)には`plugin.build_command()`が返した引数を
  そのまま使いますが、`Evidence.command`(証跡として保存・CLI/Web API/Web UI/
  Markdownレポートに表示される側)には`core/secrets.py::mask_command()`を
  通した後のコピーを格納します。`--token`/`--password`/`--cookie`/`--header`
  等それらしい名前のフラグの値を`***`に置換するキーワードヒューリスティックで、
  固定のツール別フラグ一覧ではありません(将来認証情報を扱うプラグインを
  追加した時のため。現状どのプラグインも認証情報を引数に含めないため実害は
  無いが、追加後に気付いても手遅れな種類の設計のため先に用意してあります)。
  単一文字のフラグ(例: `-H`)はキーワード照合の対象にならないため対象外です。
- `SqlmapPlugin`はさらに一段階、プラグイン固有の強制を持ちます:
  `--risk`/`--level`(検出ペイロードの積極度)には上限を設けない一方、
  OS/レジストリ/ファイル操作やインタラクティブシェルに相当するオプション
  (`os-shell`, `file-write`, `tamper`, `c` 等)は`build_command()`が
  常に`PluginError`で拒否します。これはSQLi検出の範囲を超えて対象ホスト・
  その先のネットワークへスコープが逸脱するのを防ぐためで、risk/levelの値には
  依存しません(詳細は[docs/sqlmap.md](sqlmap.md))。
- **コマンド組み立てと実行を分離する**: プラグインは `build_command`/`normalize` の
  みを担当し、実際に外部プロセスを起動するのは `ScanRunner`（`LabManager` も同様の
  分離）に一本化しています。証跡の保存形式やファイルパスは `evidence/` が一元管理し、
  プラグインが独自形式で永続化することはありません（中間出力を一時ファイルに書いても
  `normalize` 内で読み込み次第削除します）。
- **フロントエンドは薄いラッパーに留める**: CLI・Web UI(`src/pownforge/web/`)・
  Emacs連携(`emacs/pownforge.el`)はいずれも見た目が違うだけで、スコープ検証・
  プラグイン実行・証跡保存のロジックを個別に再実装しません。Web UIは
  `ScopePolicy`/`ScanRunner`をFastAPI経由で呼ぶだけ、Emacs連携は`pownforge`
  実行バイナリをサブプロセスとして呼ぶだけです。ライブ進捗も、根は
  `ScanRunner.run()`の`on_line`コールバック1つ(Web UIはWebSocketへ、
  CLI/Emacsは`--live`で標準出力へ中継)を両方が共有しています。

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
- `expected_kind: TargetKind | None`（クラス属性、既定`None`）: このプラグインの
  addressが前提とする`Target.kind`を宣言する（`None`=制約なし）。`build_command()`
  冒頭で`self.require_kind(target)`を呼ぶと、`target.kind`が一致しない場合に
  `PluginError`を送出する。どのプラグインを実行できるかの判定
  （`allowed_plugins`）には関与しない、純粋にaddress形式の前提を早期に検証する
  ためのもの。`kind_hint: str | None`で、エラーメッセージに追加のヒント
  （`SqlmapPlugin`なら「addressにインジェクション対象パラメータを含める」等）を
  付加できる。6プラグイン全てがこれを宣言している（`NetworkPlugin`のみ`None`）

`normalize()`が返す辞書に`"_findings"`キー（`{"title", "severity", "detail"}`の
リスト）を含めると、`ScanRunner`がそれを取り出して`Finding`（`source="tool"`）に
変換し`RunRecord.findings`へ格納します（`NucleiPlugin`/`KubernetesPlugin`/
`SqlmapPlugin`/`ContainerPlugin`が使用）。`KubernetesPlugin`(`trivy k8s`)と
`ContainerPlugin`(`trivy image`)は同じtrivy JSON形状
(`Results[].{Misconfigurations,Vulnerabilities,Secrets}`)を扱うため、抽出ロジックは
`src/pownforge/plugins/_trivy.py::findings_from_trivy_results()`として共通化しています。
このキーを使わないプラグイン（`NetworkPlugin`/`WebPlugin`）には影響しません。ツール側の
severity表記が`Severity` enumに合わない場合は`info`にフォールバックし、
finding自体は破棄しません（`core/finding_utils.py::coerce_finding`、
`pownforge analyze`のJSON解析と共通のロジックを使っています）。

## Target model

```python
class Target(BaseModel):
    name: str
    kind: TargetKind              # host | url（プラグインが使うaddress形式）
    address: str
    allowed_plugins: list[str]
    notes: str | None
    type: TargetType | None       # network | web | api | kubernetes | container（分類用、任意）
    environment: TargetEnvironment  # local-lab(既定) | staging | production
```

`type`は`kind`(address形式)とは独立した、レポート/一覧表示用の分類軸です。
どのプラグインを実行できるかは引き続き`allowed_plugins`だけが決めます
(`type`はスキャン実行を許可/拒否する判定には使いません)。`environment`は
「どれだけ本番/権威的な対象か」を表し、`production`だけは上記の通り
`notes`必須というコード上の強制が入ります。`kubernetes`タイプの対象は
`address`にkubeconfigのcontext名を格納します(詳細は
[docs/kubernetes.md](kubernetes.md))。`container`タイプの対象は`address`に
コンテナイメージの参照を格納します(詳細は[docs/container.md](container.md))。

## Emacs連携

`emacs/pownforge.el`は`pownforge`実行バイナリをサブプロセスとして呼び出す
Elisp front-endです。詳細は[docs/emacs.md](emacs.md)を参照。
