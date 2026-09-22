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

Python 3.11以上が必要です(`pyproject.toml` の `requires-python`)。
グローバルのPythonが古い環境でも動くよう、`make install` は `python3.11` で
`.venv` を作成してからインストールします。

```bash
make install
```

## テスト

```bash
make test
```

コードを変更したら、関連するテストを実行してから提案・コミットしてください。
新しいプラグインやコア機能を追加した場合は、対応するテストを `tests/` に追加します。

## コーディング方針

- CLI: Typer
- データモデル・入力検証: Pydantic
- 外部ツール（nmap/ffuf/docker/llm等）の**コマンド組み立て**は `plugins/` のプラグイン（`build_command`）または `core/lab.py` の `LabManager` に閉じ込める。**実際に `subprocess` を実行するのは** `core/runner.py`（`ScanRunner`）・`core/lab.py`（`LabManager`）・`ai/ollama.py` に限定し、証跡記録（タイムスタンプ・ハッシュ・タイムアウト）をそこに集約する。`cli.py` から直接 `subprocess` を呼ばない
- プラグインは「（`ScanRunner`がスコープ検証済みのTargetを渡す）→ `build_command` → `normalize`」の順で責務を分離する。中間出力（nmapのXML、ffufのJSON等）を一時ファイルに書いてもよいが、`normalize` 内で読み込み次第削除し、最終的な証跡は `evidence/`（`EvidenceStore`）経由でのみ永続化する
- 新しい外部ツールを追加する場合は `plugins/base.py` の `Plugin` を実装する
- コメントは自明でない理由（WHY）がある場合のみ、最小限で記述する

## セキュリティ・スコープ上の制約（重要）

- `config/targets.yaml` に登録されていない対象へスキャンを実行するコードを書かない・提案しない
- 対象を登録できる経路は `pownforge target add` / `pownforge lab add` / Web API（`POST /api/targets`, `POST /api/lab`）に限定する。いずれも最終的に `ScopePolicy.add_target()` を通るため、これ以外の独自の登録経路（`targets.yaml` への直接書き込みなど、`ScopePolicy` を経由しない変更）を追加しない
- Web層（`src/pownforge/web/`）のルーターは `ScopePolicy`/`ScanRunner`/`LabManager`/`EvidenceStore` を呼び出すだけの薄いラッパーに保つ。スコープ検証・ラボネットワークの`--internal`制約をWeb側で再実装・迂回しない。`pownforge web serve` の既定バインドは `127.0.0.1` のみとし、認証機構が無いことを踏まえて他インターフェースへのバインドはユーザーに確認を取る
- テスト・ローカル検証は `127.0.0.1` や自分のラボ環境など、明示的に許可された対象のみに対して行う
- `core/policy.py` のスコープ検証ロジックを弱める変更（対象名チェックの無効化、`allowed_plugins` の無視など）は、ユーザーに明示的に確認を取ってから行う
- スキャン範囲を自動的に拡大する機能（対象リストの自動探索・自動追加など）を、ユーザーの明示的な依頼なしに実装しない
- `core/lab.py` のラボネットワーク（既定 `pownforge-lab`）は常に `docker network create --internal` で作成する前提を維持する。外部到達可能なネットワークに変更する場合はユーザーに確認を取る

## コミットルール

- コミットはユーザーから明示的に依頼されたときのみ作成する
- 1コミット1関心事を基本とする（機能追加・バグ修正・リファクタリングを混在させない）
- `git push --force`、`git reset --hard`、コミットの `--amend` はユーザーが明示的に指示した場合のみ行う
- pre-commit相当のチェック（lint/test）が失敗した場合、`--no-verify` で回避せず原因を修正してから再コミットする
- 秘密情報（APIキー、認証情報、実在の対象の個人情報等）を含む可能性のあるファイルはコミットに含めない

### コミットメッセージ規約

- 日本語で記述する
- 1行目は Conventional Commits 風に `type(scope): 要約` の形式にする
  - 例:
    - `feat(scripts): rbac_audit.py にトークン昇格チェーン検出を追加`
    - `fix(kind): calico rollout の CRD 競合状態を修正`
    - `docs(agents): 攻撃チェーン検出の設計方針を追記`
    - `chore(gitignore): __pycache__ を除外`
  - `type` は `feat`（機能追加）/ `fix`（不具合修正）/ `docs`（ドキュメント）/
    `chore`（雑務・設定変更）/ `refactor`（挙動を変えないコード整理）などから選ぶ
  - `scope` はディレクトリ名や機能名を使う（例: `scripts`, `docker`, `kind`, `manifests`,
    `agents`, `core`, `plugins`, `cli`, `evidence`, `web`, `api`, `frontend` など）
- 本文（任意）は `- ` の箇条書きで変更点を列挙する。詳細な経緯や検証結果を
  書く場合もこの形式に合わせる
- 破壊的変更や既存の証跡フォーマットに影響する変更は、本文の箇条書きにその旨を明記する

## ディレクトリ構成の概要

- `src/pownforge/cli.py`: Typerエントリポイント
- `src/pownforge/core/`: モデル・スコープポリシー・実行エンジン・プラグインレジストリ・ラボネットワーク管理（`lab.py`）
- `src/pownforge/plugins/`: 個別ツール（nmap, ffuf 等）のプラグイン実装
- `src/pownforge/evidence/`: 実行証跡（コマンド・タイムスタンプ・ハッシュ）の保存
- `src/pownforge/reporting/`: Markdownレポート生成
- `src/pownforge/ai/`: ローカルLLM（Ollama経由）による分析アダプタ
- `config/targets.yaml`: 登録済みの許可対象（バージョン管理する）
- `config/wordlists/`: ffuf等で使う動作確認用ワードリスト
- `src/pownforge/web/`: FastAPIバックエンド（optional extra `[web]`）。`ScopePolicy`/
  `ScanRunner`/`LabManager`/`EvidenceStore` を呼ぶだけの薄いルーター群
- `webui/`: React製フロントエンド（Python packageの外、npmで別ビルド）。現状は
  閲覧系画面(Dashboard/Targets/Lab/Runs/Run detail)とAnalyze実行のみで、
  target登録・lab起動・新規スキャンのフォームは未実装
- `docs/lab.md`: ラボネットワーク機能（`pownforge lab`）の使い方
- `docs/web.md`: Web UI/APIの使い方
- `docs/walkthrough.md`: 実機（OWASP Juice Shop等）での検証記録
- `.pownforge/`: 実行時の状態（runs, reports）。gitignore対象
