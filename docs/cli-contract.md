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
| `pownforge result list` | 実行結果の一覧 |
| `pownforge result show <run-id>` | 実行結果の詳細（JSON） |
| `pownforge report generate <run-id>` | Markdownレポートを `.pownforge/reports/` に生成 |
| `pownforge analyze <run-id>` | ローカルLLMによる分析草案を出力 |
| `pownforge lab add <name> --image <image> [--kind host\|url] [--port <n>] [--scheme http\|https] [--env k=v ...] [--allowed-plugins a,b] [--no-register] [--network <name>]` | 隔離ネットワーク上に攻撃対象ホストを起動し、既定でスコープにも登録（`--kind url` は `--port` 必須） |
| `pownforge lab list [--network <name>]` | 稼働中/停止中のラボホスト一覧 |
| `pownforge lab remove <name> [--purge] [--network <name>]` | ラボホストを停止・削除（`--purge` でスコープからも削除） |

`--config`（既定: `config/targets.yaml`）はスコープファイルを読み書きするコマンド
（`target list/add`、`scan network/web`、`lab add/remove`）だけが受け付けます。
`--workdir` / `POWNFORGE_HOME`（既定: `.pownforge/`）は実行状態を読み書きする
コマンド（`init`、`scan network/web`、`result list/show`、`report generate`、
`analyze`）だけが受け付けます。`plugin list/info` と `lab list` はどちらも
取りません。
`scan` は登録済みの対象名しか受け付けず、任意のホスト名・URLを直接指定することはできません。
