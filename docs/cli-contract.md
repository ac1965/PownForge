# CLIコマンド契約

| コマンド | 説明 |
| --- | --- |
| `pownforge init` | 作業ディレクトリ（`.pownforge/`）と空のスコープファイルを作成 |
| `pownforge target list` | 登録済み対象の一覧 |
| `pownforge target add <name> --address <addr> [--kind host\|url] [--type network\|web\|api\|kubernetes] [--environment local-lab\|staging\|production] [--allowed-plugins a,b] [--notes <text>]` | 対象を登録。`type`は分類用の任意項目（スキャン許可判定には使わない）。`--environment production`は`--notes`（認可/契約の参照）が必須、無いと登録は拒否される |
| `pownforge plugin list` | 利用可能なプラグインと外部ツールの有無 |
| `pownforge plugin info <name>` | プラグインの詳細（`expected kind`は`--kind host\|url\|any`のうちそのプラグインが前提とするaddress形式。一致しない対象で`scan`すると即座に拒否される） |
| `pownforge scan network --target <name> [--option k=v ...] [--live]` | networkプラグイン（nmap）を実行 |
| `pownforge scan web --target <name> --option wordlist=<path> [--live]` | webプラグイン（ffuf）を実行 |
| `pownforge scan nuclei --target <name> [--option tags=... --option severity=... --option templates=...] [--live]` | nucleiプラグイン（テンプレートベースの脆弱性検出）を実行。検出結果はそのままfinding（`source: "tool"`、既定`needs-review`）として記録 |
| `pownforge scan kubernetes --target <name> [--option namespaces=... --option severity=...] [--live]` | kubernetesプラグイン（`trivy k8s`によるクラスタの誤設定/RBAC/イメージ脆弱性検出）を実行。対象の`address`はhost/URLではなくkubeconfigのcontext名を指定する。検出結果もnucleiと同様finding（`source: "tool"`）として記録 |
| `pownforge scan sqlmap --target <name> [--option risk=... --option level=... --option dump=true ...] [--live]` | sqlmapプラグイン（SQLインジェクション検出/抽出）を実行。対象の`address`はインジェクション対象パラメータを含むURL（`--kind url`）。`--risk`/`--level`に上限は無いが、OS/レジストリ/ファイル操作・シェル・設定ファイル読み込みに相当するオプション（`os-shell`, `file-write`, `tamper`, `c` 等）は常に拒否される（詳細は[docs/sqlmap.md](sqlmap.md)）。検出結果はfinding（`source: "tool"`、severity `critical`）として記録 |
| `pownforge scan container --target <name> [--option severity=... --option ignore-unfixed=true --option scanners=...] [--live]` | containerプラグイン（`trivy image`によるイメージの脆弱性/誤設定/シークレット検出）を実行。対象の`address`はhost/URLではなくコンテナイメージの参照（例: `nginx:1.25`）を指定する。検出結果もkubernetesプラグインと同様finding（`source: "tool"`）として記録（詳細は[docs/container.md](container.md)） |
| `pownforge result list` | 実行結果の一覧 |
| `pownforge result show <run-id>` | 実行結果の詳細（JSON） |
| `pownforge result review <run-id> <finding-id> <needs-review\|confirmed\|false-positive>` | findingの検証状態を更新 |
| `pownforge report generate <run-id> [--format markdown\|html]` | レポート(既定Markdown、`--format html`でスタンドアロンHTML)を `.pownforge/reports/<run-id>.{md,html}` に生成（findingsは検証状態別に見出しを分けて出力）。HTMLはWeb UIと同じseverity配色 |
| `pownforge analyze <run-id>` | ローカルLLMによる分析草案を出力 |
| `pownforge lab add <name> --image <image> [--kind host\|url] [--port <n>] [--scheme http\|https] [--env k=v ...] [--allowed-plugins a,b] [--no-register] [--network <name>]` | 隔離ネットワーク上に攻撃対象ホストを起動し、既定でスコープにも登録（`--kind url` は `--port` 必須） |
| `pownforge lab list [--network <name>]` | 稼働中/停止中のラボホスト一覧 |
| `pownforge lab remove <name> [--purge] [--network <name>]` | ラボホストを停止・削除（`--purge` でスコープからも削除） |
| `pownforge audit list` | `ScopePolicy` が拒否したスキャン実行の試みを一覧表示 |
| `pownforge audit show <violation-id>` | 拒否された試みの詳細（JSON） |
| `pownforge evidence verify <run-id>` | 保存済みoutputからstdout/stderrのSHA-256を再計算し、証跡のハッシュと一致するか確認 |

`--config`（既定: `config/targets.yaml`）はスコープファイルを読み書きするコマンド
（`target list/add`、`scan network/web`、`lab add/remove`）だけが受け付けます。
`--workdir` / `POWNFORGE_HOME`（既定: `.pownforge/`）は実行状態を読み書きする
コマンド（`init`、`scan network/web`、`result list/show/review`、
`report generate`、`analyze`、`audit list/show`、`evidence verify`）だけが
受け付けます。
`plugin list/info` と `lab list` はどちらも取りません。
`scan` は登録済みの対象名しか受け付けず、任意のホスト名・URLを直接指定することはできません。
各プラグインは前提とする`Target.kind`(`plugin info`の`expected kind`)を宣言しており、
一致しない対象で`scan`を実行すると（ツールを起動する前に）明確な`PluginError`で拒否されます
（`network`は`any`で制約なし、`web`/`nuclei`/`sqlmap`は`url`、`kubernetes`/`container`は`host`）。
拒否された試み（`config/targets.yaml`未登録の対象や許可されていないプラグインへの
`scan`実行）は`.pownforge/violations/`に記録され、コマンド自体は一切実行されません。

`evidence verify`は、実行結果JSONファイルへの偶発的・部分的な変更（誤編集や
ディスク破損など）を検出するためのものです。そのファイルを編集できる権限を
持つ人は証跡のハッシュ自体も書き換えられるため、悪意ある改ざんに対する証明には
なりません（詳細はAGENTS.mdを参照）。

`stdout_sha256`/`stderr_sha256`は`output`（実際のツール出力）に対するハッシュで、
`evidence.command`（`--token`/`--password`等それらしい値を`***`にマスクした後の
コピー）は`evidence verify`の対象ではありません。マスクは表示・保存専用で、
実際に実行されたコマンドはマスク前の引数のままです（詳細は
[docs/architecture.md](architecture.md)）。

`--live`はツールのstdoutを1行ずつ`| `付きでその場に表示するだけで、保存される
証跡・findingの内容は`--live`の有無に関わらず同一です（Web UIのWebSocket
ライブ進捗と同じ`ScanRunner`の`on_line`コールバックを使っているだけ）。
Emacs連携（`emacs/pownforge.el`、[docs/emacs.md](emacs.md)）はこの`--live`出力を
非同期プロセスのバッファへライブテールする形で利用しています。
