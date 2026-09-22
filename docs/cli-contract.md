# CLIコマンド契約

| コマンド | 説明 |
| --- | --- |
| `pownforge init` | 作業ディレクトリ（`.pownforge/`）と空のスコープファイルを作成 |
| `pownforge target list` | 登録済み対象の一覧 |
| `pownforge target add <name> --address <addr> [--kind host\|url] [--allowed-plugins a,b]` | 対象を登録 |
| `pownforge plugin list` | 利用可能なプラグインと外部ツールの有無 |
| `pownforge plugin info <name>` | プラグインの詳細 |
| `pownforge scan network --target <name> [--option k=v ...]` | networkプラグイン（nmap）を実行 |
| `pownforge scan web --target <name> --option wordlist=<path>` | webプラグイン（ffuf）を実行 |
| `pownforge scan nuclei --target <name> [--option tags=... --option severity=... --option templates=...]` | nucleiプラグイン（テンプレートベースの脆弱性検出）を実行。検出結果はそのままfinding（`source: "tool"`、既定`needs-review`）として記録 |
| `pownforge scan kubernetes --target <name> [--option namespaces=... --option severity=...]` | kubernetesプラグイン（`trivy k8s`によるクラスタの誤設定/RBAC/イメージ脆弱性検出）を実行。対象の`address`はhost/URLではなくkubeconfigのcontext名を指定する。検出結果もnucleiと同様finding（`source: "tool"`）として記録 |
| `pownforge result list` | 実行結果の一覧 |
| `pownforge result show <run-id>` | 実行結果の詳細（JSON） |
| `pownforge result review <run-id> <finding-id> <needs-review\|confirmed\|false-positive>` | findingの検証状態を更新 |
| `pownforge report generate <run-id>` | Markdownレポートを `.pownforge/reports/` に生成（findingsは検証状態別に見出しを分けて出力） |
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
拒否された試み（`config/targets.yaml`未登録の対象や許可されていないプラグインへの
`scan`実行）は`.pownforge/violations/`に記録され、コマンド自体は一切実行されません。

`evidence verify`は、実行結果JSONファイルへの偶発的・部分的な変更（誤編集や
ディスク破損など）を検出するためのものです。そのファイルを編集できる権限を
持つ人は証跡のハッシュ自体も書き換えられるため、悪意ある改ざんに対する証明には
なりません（詳細はAGENTS.mdを参照）。
