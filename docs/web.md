# Web UI / API

`pownforge web serve` で、CLIと同じコア(`ScopePolicy`/`ScanRunner`/`LabManager`/
`EvidenceStore`)をそのまま使うFastAPIバックエンドを起動できます。スキャンの
ライブ進捗はWebSocketでストリーミングされます。

> **現在の状況:** バックエンドAPI（本ドキュメントの内容）は実装・テスト済みです。
> React製のフロントエンド(`webui/`)は次の実装段階で追加予定で、まだこの
> リポジトリには含まれていません。それまでは`curl`やWebSocketクライアントで
> APIを直接操作するか、`/docs`（Swagger UI）から試せます。

## セットアップ

```bash
pip install -e ".[web]"
pownforge web serve
```

- 既定は `http://127.0.0.1:8420`。`--host`/`--port`/`--config`/`--workdir`で変更可能。
- **セキュリティ:** 既定で`127.0.0.1`のみにバインドします。認証機構は
  このバージョンにはありません（ローカル単一ユーザー前提）。`--host 0.0.0.0`
  等で他インターフェースにバインドすると、target登録・lab起動・スキャン実行の
  書き込み系APIがそのまま露出します。信頼できないネットワークでは使わないでください。
- Swagger UI: `http://127.0.0.1:8420/docs`

## APIエンドポイント

すべてのハンドラは`ScopePolicy`/`ScanRunner`/`LabManager`をそのまま呼ぶだけの
薄いラッパーです。CLIを経由してもWeb APIを経由しても、認可ロジック
（`config/targets.yaml`に登録された対象・プラグインの組み合わせでしか
スキャンできない、ラボネットワークは常に`--internal`、等）は同じです。

| メソッド/パス | 説明 |
| --- | --- |
| `GET /api/targets` | 登録済み対象の一覧 |
| `POST /api/targets` | 対象を登録（`ScopePolicy.add_target`） |
| `DELETE /api/targets/{name}` | 対象を削除 |
| `GET /api/plugins` | プラグイン一覧と外部ツールの有無 |
| `GET /api/lab` | 稼働中/停止中のラボホスト一覧 |
| `POST /api/lab` | ラボホストを起動（既定でスコープにも自動登録） |
| `DELETE /api/lab/{name}?purge=true` | ラボホストを削除（`purge`でスコープからも削除） |
| `POST /api/scans` | スキャンをジョブとして投入。`{"job_id": ..., "status": "pending"}`を返す |
| `GET /api/scans/{job_id}` | ジョブの状態をポーリング（`pending/running/done/error`） |
| `WS /api/ws/scans/{job_id}` | スキャンのライブ出力を行単位でストリーミング |
| `GET /api/runs` | 実行結果の一覧 |
| `GET /api/runs/{run_id}` | 実行結果の詳細（JSON） |
| `GET /api/runs/{run_id}/report` | Markdownレポート文字列を返す |
| `POST /api/runs/{run_id}/analyze` | ローカルLLMで分析・分類し、結果を永続化 |

## WebSocketメッセージ形式

`WS /api/ws/scans/{job_id}` は次のいずれかのJSONメッセージを送信します。

```json
{"type": "line", "data": "Nmap scan report for ..."}
{"type": "done", "run_id": "abcd1234", "returncode": 0}
{"type": "error", "message": "'nmap' is required for the 'network' plugin but was not found on PATH..."}
```

`done`または`error`が届いたら接続は終了します。**1ジョブにつき1接続**のみを
想定した設計です（キューは単一購読者向けで、途中から再接続しても、それまでに
流れた行は再取得できません。ジョブの現在状態だけなら`GET /api/scans/{job_id}`
で確認できます）。

## 使用例

```bash
curl -X POST http://127.0.0.1:8420/api/targets \
  -H 'Content-Type: application/json' \
  -d '{"name":"lab-net","kind":"host","address":"127.0.0.1","allowed_plugins":["network"]}'

curl -X POST http://127.0.0.1:8420/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"lab-net","plugin":"network","options":{"ports":"3000"}}'
# => {"job_id": "...", "status": "pending"}

# 別途、job_idを使ってWebSocketでライブ出力を購読する
```

## テスト

```bash
pip install -e ".[dev,web]"
pytest
```

`tests/web/`配下のテストは冒頭で`pytest.importorskip("fastapi")`しているため、
`[web]`をインストールしていない環境でも`pytest`全体は失敗せず、該当テストは
skipされます。
