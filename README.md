# PownForge

許可されたラボ・検証環境向けの、モジュール型セキュリティ診断CLIです。
Pown.js の「独立したモジュールをCLIから呼び出す」という考え方を参考にしていますが、実装はPython/Typerによる独自設計です。

対象範囲の検証（`config/targets.yaml`）、外部ツールの実行、結果の正規化、証跡保存、
ローカルLLM（Ollama）によるレポート草案作成までを一貫して行います。

> **重要:** このツールは、明示的に許可された対象に対してのみ使用してください。
> `config/targets.yaml` に登録されていない対象はスキャンできない設計になっています。

## セットアップ

Python 3.11以上が必要です(`pyproject.toml` の `requires-python`)。
`make install` は `python3.11` で `.venv` を自動作成してインストールします。

```bash
make install
```

`make` 経由を使わない場合は、Python 3.11以上の仮想環境を用意してから:

```bash
pip install -e ".[dev]"
```

## クイックスタート

`pownforge` は `.venv` の中にインストールされているため、シェルのPATHには
自動では入りません。先に仮想環境を有効化してください(以降 `pownforge ...`
は `.venv/bin/pownforge ...` と同じ意味になります)。

```bash
source .venv/bin/activate
```

毎回有効化したくない場合は、コマンドの前に `.venv/bin/` を付けて
(`.venv/bin/pownforge init` のように)直接呼び出すこともできます。

```bash
# 作業ディレクトリと空のスコープファイルを初期化
pownforge init

# 利用可能なプラグインを確認（"missing tool" と出た場合、そのプラグインの
# 外部ツールがホストに無い。network なら `brew install nmap` 等でホストに
# 直接入れるか、代わりに Dockerランタイム(docs/lab.md参照)を使う）
pownforge plugin list

# 検証対象を登録（自分のラボ環境などに限定すること）
pownforge target add lab-web --address 127.0.0.1 --kind host --allowed-plugins network

# 登録済み対象一覧
pownforge target list

# 診断を実行
pownforge scan network --target lab-web

# 実行結果一覧・詳細
pownforge result list
pownforge result show <run-id>

# Markdownレポート生成
pownforge report generate <run-id>

# ローカルLLMによる分析（~/.local/bin/llm 経由でOllamaを利用）
pownforge analyze <run-id>
```

## ラボ環境（攻撃対象ホストの動的追加）

`pownforge lab add/list/remove` で、隔離されたDockerネットワーク上に
攻撃対象ホストを動的に起動・停止できます。詳細は [docs/lab.md](docs/lab.md) を
参照してください。OWASP Juice Shopに対する実スキャンでの検証記録は
[docs/walkthrough.md](docs/walkthrough.md) を参照してください。

## Web UI / API

`pip install -e ".[web]"` の上で `pownforge web serve` を実行すると、CLIと
同じコアをそのまま使うFastAPIバックエンドが起動します。React製フロントエンド
(`webui/`)からtargetの追加・削除、labホストの起動・削除、新規スキャンの実行
(WebSocketによるライブ進捗表示)、AI分析、finding検証、evidence検証まで、
ひととおりの操作がブラウザだけで完結します。詳細は
[docs/web.md](docs/web.md) を参照してください。

## アーキテクチャ

設計の詳細は [docs/architecture.md](docs/architecture.md) と [docs/cli-contract.md](docs/cli-contract.md) を参照してください。
設計当初のロードマップとの対比・今後の優先順位は [docs/roadmap.md](docs/roadmap.md) にまとめています。

## 開発

```bash
make install
make test
```

コミット規約・エージェント向けの運用ルールは [AGENTS.md](AGENTS.md) にまとめています。

## 現在の実装範囲（Phase 1）

- CLI基盤（Typer）
- 対象管理・スコープ検証（`core/policy.py`）
- プラグインレジストリと `network`（nmap）/ `web`（ffuf）/ `nuclei`（テンプレートベース脆弱性検出）/
  `kubernetes`（`trivy k8s`によるクラスタ誤設定・RBAC・イメージ脆弱性検出）。各ツールの出力は
  構造化データに正規化し、nuclei/kubernetesは検出結果をfinding（`source: "tool"`）としても記録
- 隔離Dockerネットワーク上への攻撃対象ホストの動的追加（`pownforge lab`）
- Web API + ライブ進捗WebSocket（`pownforge web serve`、optional extra `[web]`）+ React製の閲覧用SPA（`webui/`）
- 実行証跡（コマンド・タイムスタンプ・SHA-256ハッシュ）の保存
- Markdownレポート生成
- ローカルLLM（Ollama）分析アダプタ

高度な結果正規化（重大度判定・脆弱性分類の自動化など）は今後のフェーズで拡張します。
