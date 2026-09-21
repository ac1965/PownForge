# PownForge

許可されたラボ・検証環境向けの、モジュール型セキュリティ診断CLIです。
Pown.js の「独立したモジュールをCLIから呼び出す」という考え方を参考にしていますが、実装はPython/Typerによる独自設計です。

対象範囲の検証（`config/targets.yaml`）、外部ツールの実行、結果の正規化、証跡保存、
ローカルLLM（Ollama）によるレポート草案作成までを一貫して行います。

> **重要:** このツールは、明示的に許可された対象に対してのみ使用してください。
> `config/targets.yaml` に登録されていない対象はスキャンできない設計になっています。

## セットアップ

```bash
pip install -e ".[dev]"
```

## クイックスタート

```bash
# 作業ディレクトリと空のスコープファイルを初期化
pownforge init

# 利用可能なプラグインを確認
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

## アーキテクチャ

設計の詳細は [docs/architecture.md](docs/architecture.md) と [docs/cli-contract.md](docs/cli-contract.md) を参照してください。

## 開発

```bash
make install
make test
```

コミット規約・エージェント向けの運用ルールは [AGENTS.md](AGENTS.md) にまとめています。

## 現在の実装範囲（Phase 1）

- CLI基盤（Typer）
- 対象管理・スコープ検証（`core/policy.py`）
- プラグインレジストリと `network`（nmap）/ `web`（ffuf）の最小実装
- 実行証跡（コマンド・タイムスタンプ・SHA-256ハッシュ）の保存
- Markdownレポート生成
- ローカルLLM（Ollama）分析アダプタ

高度な結果正規化（重大度判定・脆弱性分類の自動化など）は今後のフェーズで拡張します。
