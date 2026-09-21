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

すべてのコマンドは `--config`（既定: `config/targets.yaml`）と
`--workdir` / `POWNFORGE_HOME`（既定: `.pownforge/`）で保存先を変更できます。
`scan` は登録済みの対象名しか受け付けず、任意のホスト名・URLを直接指定することはできません。
