# ラボネットワーク（攻撃対象ホストの動的追加）

`pownforge lab` サブコマンドは、意図的に脆弱なコンテナイメージを
「攻撃対象ホスト」として、隔離されたDockerネットワーク上に動的に
起動・停止するための機能です。`compose.yaml` を手動編集してサービスを
追加する必要はありません。

## 安全設計

- ラボ用ネットワーク（既定名: `pownforge-lab`）は `docker network create --internal`
  で作成され、外部ネットワーク（インターネットやホストの他のネットワーク）へは
  ルーティングされません。すでに同名のネットワークが存在する場合は、その設定を
  尊重してそのまま使います（作り直しません）。
- `pownforge lab add` で追加したホストは、既定で `config/targets.yaml` にも
  自動登録されます（`--no-register` で無効化可能）。スキャンは引き続き
  `ScopePolicy` による対象名の検証を経由するため、ラボホストを追加しただけで
  スキャン範囲が無条件に広がることはありません。
- 実際のスキャン（`pownforge scan ...`）は、`pownforge-lab` ネットワークに
  接続されたコンテナ（`docker compose run pownforge ...` など）から実行して
  ください。ホストマシンから直接実行すると、Dockerの組み込みDNSによる
  コンテナ名解決が効かず対象に到達できません。

## 使い方

```bash
# 攻撃対象ホストを追加（ネットワークが無ければ自動作成）
# --kind host: nmap(network)プラグイン向け。address はコンテナ名そのもの
pownforge lab add lab-net --image <your-vulnerable-image> --allowed-plugins network

# --kind url --port <port>: web/apiプラグイン向け。address は http(s)://<name>:<port>
pownforge lab add lab-web --image bkimminich/juice-shop --kind url --port 3000 --allowed-plugins web,network

# 稼働中のラボホスト一覧
pownforge lab list

# スキャンは pownforge-lab ネットワークに接続したコンテナから実行する
docker compose run --rm pownforge scan network --target lab-net
docker compose run --rm pownforge scan web --target lab-web \
  --option wordlist=/app/config/wordlists/common.txt

# 不要になったら停止・削除（--purge でスコープからも削除）
pownforge lab remove lab-web --purge
```

`config/wordlists/common.txt` は動作確認用の最小限のワードリストです。
実運用では SecLists 等、より網羅的なワードリストに差し替えてください。

ラボイメージ自体はこのリポジトリに含まれません。自分が使用権限を持つ、
意図的に脆弱なイメージ（自作のラボ環境、購入・利用許諾済みの教材イメージ等）を
指定してください。
