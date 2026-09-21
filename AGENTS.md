# AGENTS.md

このリポジトリで作業するすべてのAIエージェント（Claude Code等）向けの運用ルールです。

## プロジェクト概要

PownForge は、許可された検証環境・ラボ環境に対するセキュリティ診断を、
プラグイン方式で実行・正規化・証跡管理するためのCLIです。
Pown.js の「モジュールを独立させ、CLIから呼び出す」という思想を参考にしていますが、
実装はPython/Typerによる独自設計です。

詳細な設計方針は [docs/architecture.md](docs/architecture.md) を、
コマンド一覧は [docs/cli-contract.md](docs/cli-contract.md) を参照してください。

## セットアップ

```bash
pip install -e ".[dev]"
```

## テスト

```bash
pytest
```

コードを変更したら、関連するテストを実行してから提案・コミットしてください。
新しいプラグインやコア機能を追加した場合は、対応するテストを `tests/` に追加します。

## コーディング方針

- CLI: Typer
- データモデル・入力検証: Pydantic
- 外部ツール呼び出しは `plugins/` 配下のプラグインに閉じ込め、`cli.py` や `core/` から直接 `subprocess` を呼ばない
- プラグインは「対象の検証 → コマンド実行 → 出力正規化」の順で責務を分離し、独自形式で証跡を保存しない（`evidence/` 経由にする）
- 新しい外部ツールを追加する場合は `plugins/base.py` の `Plugin` を実装する
- コメントは自明でない理由（WHY）がある場合のみ、最小限で記述する

## セキュリティ・スコープ上の制約（重要）

- `config/targets.yaml` に登録されていない対象へスキャンを実行するコードを書かない・提案しない
- `pownforge target add` 以外の経路で対象を追加するショートカットを作らない（スコープ検証を迂回する変更を提案しない）
- テスト・ローカル検証は `127.0.0.1` や自分のラボ環境など、明示的に許可された対象のみに対して行う
- `core/policy.py` のスコープ検証ロジックを弱める変更（対象名チェックの無効化、`allowed_plugins` の無視など）は、ユーザーに明示的に確認を取ってから行う
- スキャン範囲を自動的に拡大する機能（対象リストの自動探索・自動追加など）を、ユーザーの明示的な依頼なしに実装しない

## コミットルール

- コミットはユーザーから明示的に依頼されたときのみ作成する
- 1コミット1関心事を基本とする（機能追加・バグ修正・リファクタリングを混在させない）
- コミットメッセージは以下の慣習に従う：
  - 先頭行は50文字程度の要約。動詞から始める（例: `Add network plugin`, `Fix scope validation for empty allowed_plugins`）
  - 本文が必要な場合は空行を挟み、「何を」ではなく「なぜ」を書く
  - 破壊的変更や既存の証跡フォーマットに影響する変更は、本文にその旨を明記する
- `git push --force`、`git reset --hard`、コミットの `--amend` はユーザーが明示的に指示した場合のみ行う
- pre-commit相当のチェック（lint/test）が失敗した場合、`--no-verify` で回避せず原因を修正してから再コミットする
- 秘密情報（APIキー、認証情報、実在の対象の個人情報等）を含む可能性のあるファイルはコミットに含めない

## ディレクトリ構成の概要

- `src/pownforge/cli.py`: Typerエントリポイント
- `src/pownforge/core/`: モデル・スコープポリシー・実行エンジン・プラグインレジストリ
- `src/pownforge/plugins/`: 個別ツール（nmap, ffuf 等）のプラグイン実装
- `src/pownforge/evidence/`: 実行証跡（コマンド・タイムスタンプ・ハッシュ）の保存
- `src/pownforge/reporting/`: Markdownレポート生成
- `src/pownforge/ai/`: ローカルLLM（Ollama経由）による分析アダプタ
- `config/targets.yaml`: 登録済みの許可対象（バージョン管理する）
- `.pownforge/`: 実行時の状態（runs, reports）。gitignore対象
