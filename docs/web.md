# Web UI / API

`pownforge web serve` で、CLIと同じコア(`ScopePolicy`/`ScanRunner`/`LabManager`/
`EvidenceStore`)をそのまま使うFastAPIバックエンドを起動できます。スキャンの
ライブ進捗はWebSocketでストリーミングされます。

> **現在の状況:** バックエンドAPIとフロントエンド(`webui/`, React + Vite)の
> 閲覧系画面(Dashboard/Targets/Lab/Runs/Run detail、Run detailからの
> Analyze実行を含む)は実装・動作確認済みです。target登録・lab起動・新規
> スキャンのフォームはまだ画面に無く、それらはAPI経由（`curl`や`/docs`の
> Swagger UI）で行ってください。

## セットアップ

### 開発時（2ターミナル）

```bash
# ターミナル1: バックエンド
pip install -e ".[web]"
pownforge web serve

# ターミナル2: フロントエンド（初回のみ `make web-install` でnpm installも）
cd webui && npm run dev
```

`npm run dev` (Vite, 既定 `http://localhost:5173`) が `/api/*`（WebSocket含む）を
`http://127.0.0.1:8420` へプロキシするので、ブラウザからは
`http://localhost:5173` を開くだけで動きます。CORS設定は不要です。

### ビルド済みSPAをFastAPIから配信する場合

```bash
make web-build      # webui/dist を生成
pownforge web serve  # 同一オリジンでAPIとSPAの両方を配信
```

- 既定は `http://127.0.0.1:8420`。`--host`/`--port`/`--config`/`--workdir`で変更可能。
- **セキュリティ:** 既定で`127.0.0.1`のみにバインドします。認証機構は
  このバージョンにはありません（ローカル単一ユーザー前提）。`--host 0.0.0.0`
  等で他インターフェースにバインドすると、target登録・lab起動・スキャン実行の
  書き込み系APIがそのまま露出します。信頼できないネットワークでは使わないでください。
- Swagger UI: `http://127.0.0.1:8420/docs`
- **開発サーバーの既知の注意点:** `npm run dev`（Vite/esbuild）の開発サーバーは、
  ブラウザで開いている別のWebサイトからのリクエストを受け付けてしまう既知の
  問題(GHSA-67mh-4wv8-2f99)があります。信頼できるネットワーク・自分だけが
  使うマシンで動かしてください。ビルド済みSPAをFastAPI経由で配信する運用
  (`make web-build` + `pownforge web serve`)ではこの開発サーバー自体を
  使わないため影響しません。

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
| `PATCH /api/runs/{run_id}/findings/{finding_id}` | findingの検証状態(`needs-review`/`confirmed`/`false-positive`)を更新 |
| `GET /api/runs/{run_id}/verify` | 保存済みoutputからstdout/stderrのSHA-256を再計算し、証跡のハッシュと一致するか確認 |
| `GET /api/audit` | `ScopePolicy`が拒否したスキャン実行の試みを一覧表示 |
| `GET /api/audit/{violation_id}` | 拒否された試みの詳細（JSON） |

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
