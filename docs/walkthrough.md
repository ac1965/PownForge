# 検証ウォークスルー: Juice Shop に対する実スキャン

Phase 1 で実装したラボネットワーク機能(`pownforge lab`)と、
web(ffuf)/network(nmap)プラグインの結果正規化を、実際の脆弱Webアプリ
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) に対して動かして検証した記録です。
以下のコマンド・出力はすべて実機(Docker Desktop, Apple Silicon)で実際に取得したものです。

## 環境

- ホスト: macOS / Apple Silicon(M4)
- ランタイム: `docker/Dockerfile.runtime`(Arch Linux, `--platform linux/amd64` でエミュレーション実行)
- ラボネットワーク: `pownforge-lab`(`docker network create --internal`)

## 1. ランタイムイメージのビルドで遭遇した問題と対応

Arch Linux公式ベースイメージをApple Siliconでビルドすると、実運用で
つまずきやすい2つの問題が発生した。今後同じ構成で構築する場合の参考として記録する。

| 問題 | 症状 | 原因 | 対応 |
| --- | --- | --- | --- |
| プラットフォーム不一致 | `no match for platform in manifest: not found` | `archlinux:base` にarm64向けマニフェストが無い | `docker build --platform linux/amd64`、および `compose.yaml` の該当serviceに `platform: linux/amd64` を明記 |
| pacmanサンドボックス失敗 | `error restricting syscalls via seccomp: 22!` | pacmanの新しいダウンロードサンドボックスが必要とするseccomp/user-namespace系syscallをQEMUエミュレーションが未対応 | `/etc/pacman.conf` に `DisableSandbox` を追加([docker/Dockerfile.runtime](../docker/Dockerfile.runtime), [docker/Dockerfile.dev](../docker/Dockerfile.dev)) |
| ffufが見つからない | `error: target not found: ffuf` | ffufはArch公式リポジトリ(core/extra)に未収録 | `go` パッケージを追加し、`go install github.com/ffuf/ffuf/v2@latest` でソースからビルド |

ビルド後、ツールの実在を実機で確認:

```text
$ docker run --rm --platform linux/amd64 --entrypoint sh pownforge:runtime \
    -c "command -v nmap; command -v ffuf; command -v pownforge; ffuf -V; nmap --version | head -1"
/usr/sbin/nmap
/usr/local/bin/ffuf
/usr/sbin/pownforge
ffuf version: 2.1.0-dev
Nmap version 7.991 ( https://nmap.org )
```

## 2. 攻撃対象ホスト(Juice Shop)をラボネットワークに追加

```text
$ pownforge lab add lab-web --image bkimminich/juice-shop --kind url --port 3000 --allowed-plugins web,network
started lab host 'lab-web' (bkimminich/juice-shop) on network 'pownforge-lab'
registered target 'lab-web' -> http://lab-web:3000 (resolves via docker DNS on 'pownforge-lab')

$ pownforge lab list
lab-web    bkimminich/juice-shop    Up Less than a second

$ pownforge target list
lab-web    url    http://lab-web:3000    plugins=web, network
```

`pownforge-lab` ネットワークが存在しなかったため、`docker network create --internal
pownforge-lab` が自動実行された。

## 3. web プラグイン(ffuf)での実スキャン

```bash
docker compose run --rm pownforge scan web --target lab-web \
  --option wordlist=/app/config/wordlists/common.txt
```

```text
run c48691fee3c6 completed (exit=0)
```

`pownforge result show c48691fee3c6` で確認した正規化結果(抜粋、`output.hits`):

```json
[
  {"path": "robots.txt", "url": "http://lab-web:3000/robots.txt", "status": 200, "length": 9393, "words": 466},
  {"path": "api", "url": "http://lab-web:3000/api", "status": 200, "length": 9393, "words": 466},
  {"path": "rest", "url": "http://lab-web:3000/rest", "status": 200, "length": 9393, "words": 466},
  {"path": "administration", "url": "http://lab-web:3000/administration", "status": 200, "length": 9393, "words": 466},
  {"path": "encryptionkeys", "url": "http://lab-web:3000/encryptionkeys", "status": 200, "length": 7951, "words": 1474},
  {"path": ".git", "url": "http://lab-web:3000/.git", "status": 200, "length": 9393, "words": 466},
  {"path": "main.js", "url": "http://lab-web:3000/main.js", "status": 200, "length": 1207722, "words": 34636}
]
```

`WebPlugin.normalize()` は ffuf の `-o <一時ファイル> -of json` 出力を読み込み、
`hits: [{path, url, status, length, words}, ...]` の構造化リストに変換している
(改修前は生の stdout/stderr テキストのみを保持していた)。
多くのパスが `length: 9393` で揃っているのはJuice ShopのSPAが未知パスも
同一のindex.htmlで応答しているためで、実運用では `-fs` 等でこのノイズを
除外するチューニングが必要になる(今回は正規化ロジックの動作確認が目的のため未実施)。

## 4. network プラグイン(nmap)での実スキャン

まずデフォルトの上位1000ポートでスキャン(3000番はこの範囲に含まれず、ヒットなし):

```text
$ docker compose run --rm pownforge scan network --target lab-net
run ef5a40c331f4 completed (exit=0)
```

```json
"hosts": [{"address": "172.19.0.3", "ports": []}]
```

`--option ports=3000` を指定して再実行すると、実際にJuice Shopが待受けている
ポートを検出できた:

```text
$ docker compose run --rm pownforge scan network --target lab-net --option ports=3000
run d12ef0b5622d completed (exit=0)
```

```json
"hosts": [
  {
    "address": "172.19.0.3",
    "ports": [
      {"port": "3000", "protocol": "tcp", "state": "open", "service": "ppp", "product": null, "version": null}
    ]
  }
]
```

`NetworkPlugin.normalize()` は nmap の `-oX <一時ファイル>` 出力(XML)を
`xml.etree.ElementTree` でパースし、`hosts: [{address, ports: [{port, protocol,
state, service, product, version}]}]` に変換している。

## 5. レポート生成

```text
$ docker compose run --rm pownforge report generate ef5a40c331f4
wrote .pownforge/reports/ef5a40c331f4.md
```

## 検証結果サマリ

- ラボネットワーク機能(`pownforge lab add/list/remove`)がJuice Shopコンテナに対して実際に動作し、スコープ(`config/targets.yaml`)への自動登録も機能した
- web(ffuf)/network(nmap)プラグインの改修後の正規化ロジックが、実ツールの出力を実際に構造化データへ変換できることを確認した
- `pownforge report generate` がスキャン結果からMarkdownレポートを実際に生成できることを確認した
- Arch Linuxベースイメージ特有のビルド問題(プラットフォーム不一致・pacmanサンドボックス・ffuf未収録)を特定し、Dockerfileを修正した

## 後片付け

検証に使ったコンテナ・スコープ登録は本ウォークスルー作成後に削除している
(`pownforge lab remove lab-web --purge`、`docker network rm pownforge-lab`)。
再現する場合は本文の手順をそのまま実行すればよい。
