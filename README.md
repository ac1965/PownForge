# PownForge

許可されたラボ・検証環境向けの、モジュール型セキュリティ診断CLIです。
Pown.js の「独立したモジュールをCLIから呼び出す」という考え方を参考にしていますが、実装はPython/Typerによる独自設計です。

対象範囲の検証（`config/targets.yaml`）、外部ツールの実行、結果の正規化、証跡保存、
LLM（ローカルOllama、またはClaude/OpenAI等のホスト型モデル。`pownforge config`で選択）
によるレポート草案作成までを一貫して行います。

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
# 直接入れるか、代わりに Dockerランタイム(docs/handbook.md §3参照)を使う）
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

# LLMによる分析（~/.local/bin/llm 経由。使うモデル/出力言語は以下で設定）
pownforge config set --model qwen3:14b --language ja
pownforge analyze <run-id>
```

## ラボ環境（攻撃対象ホストの動的追加）

`pownforge lab add/list/remove` で、隔離されたDockerネットワーク上に
攻撃対象ホストを動的に起動・停止できます。詳細は
[docs/handbook.md §7 ラボネットワーク](docs/handbook.md#7-ラボネットワーク) を
参照してください。

> **注意:** ラボホストへの`scan`は`docker compose run pownforge ...`
> 経由で実行する必要があります（ホストマシンから直接実行するとDNSが
> 効かず到達できません）。一方、`analyze`/`walkthrough generate`は逆に
> **ホスト側の`.venv/bin/pownforge`から**実行してください（Dockerランタイムには
> `llm` CLIが無く、ラボネットワークは外部到達不可のため）。

## Web UI / API

`pip install -e ".[web]"` の上で `pownforge web serve` を実行すると、CLIと
同じコアをそのまま使うFastAPIバックエンドが起動します。React製フロントエンド
(`webui/`)からtargetの追加・削除、labホストの起動・削除、新規スキャンの実行
(WebSocketによるライブ進捗表示)、Playbook実行(ステップ単位のライブ進捗)、
AI分析、finding検証、evidence検証、複数runをまたぐウォークスルー生成まで、
ひととおりの操作がブラウザだけで完結します。詳細は
[docs/handbook.md §9 Web UI / API](docs/handbook.md#9-web-ui--api) を
参照してください。

## アーキテクチャ・全体像

設計・ビルド・利用をまとめた手引書は [docs/handbook.md](docs/handbook.md) を
参照してください。図解・実装状況サマリーも含まれています。

## 開発

```bash
make install
make test        # pytest のみ
make test-all     # pytest + webuiビルド + Emacs ERT(npm/Emacsが入っている場合)
```

コミット規約・エージェント向けの運用ルールは [AGENTS.md](AGENTS.md) にまとめています。

## 現在の実装範囲（Phase 1）

- CLI基盤（Typer）
- 対象管理・スコープ検証（`core/policy.py`）
- プラグインレジストリと `recon`（subfinder、受動的サブドメイン列挙。対象へは
  一切トラフィックを送らない）/ `network`（nmap）/ `web`（ffuf）/ `nuclei`（テンプレートベース脆弱性検出）/
  `kubernetes`（`trivy k8s`によるクラスタ誤設定・RBAC・イメージ脆弱性検出）/
  `container`（`trivy image`によるコンテナイメージの脆弱性・誤設定・シークレット検出）/
  `vulncheck`（nmapの`vuln`+`safe`分類スクリプトに限定した許可リスト方式で、
  Heartbleed/EternalBlue等の既知CVEを単一対象に対して検証。`exploit`/`intrusive`系
  スクリプトは常に拒否）/
  `sqlmap`（SQLインジェクション検出・抽出。OS/ファイル操作系オプションは常に拒否、
  詳細は[docs/handbook.md §6](docs/handbook.md#6-プラグイン)）。各ツールの出力は構造化データに正規化し、
  nuclei/kubernetes/container/sqlmapは検出結果をfinding（`source: "tool"`）としても記録
- 隔離Dockerネットワーク上への攻撃対象ホストの動的追加（`pownforge lab`）
- Web API + ライブ進捗WebSocket（`pownforge web serve`、optional extra `[web]`）+ React製の閲覧用SPA（`webui/`）
- 実行証跡（コマンド・タイムスタンプ・SHA-256ハッシュ）の保存
- Markdown/HTMLレポート生成（エグゼクティブサマリー節つき）
- 人間が別ツールで実施した工程の証跡取り込み（`pownforge result import`/`add-finding`。
  PownForge自身はコマンドを実行しない）。`--phase`で攻撃チェーン上の位置
  （discovery〜impact）を記録でき、PownForge自身が実行するのは引き続き
  discovery/vuln-confirm相当のみ
- `Engagement`(既存Targetのグループ化)による横展開の記録（`pownforge engagement add`、
  `result import --engagement/--via`。PownForgeが実際にホスト間を移動することはない）
- `Playbook`による複数プラグインの連続実行（`pownforge playbook run`。
  実行順・条件(`when`: 直前までのstepのfinding severityによる分岐)は
  人間が事前に書いたYAMLで決まり、実行時にAIが次の一手を決めることはない。
  詳細は[docs/handbook.md §8](docs/handbook.md#8-playbook-複数プラグインの連続実行)）
- LLM分析アダプタ（`llm` CLI経由。ローカルOllama/Claude/OpenAI等をモデル名で切替）
- Emacs連携（`emacs/pownforge.el`）: 対象/プラグイン一覧、`--live`によるスキャン・
  Playbookのライブ表示、findingのレビュー、Org-modeへのfindings出力
  （[docs/handbook.md §10](docs/handbook.md#10-emacs連携)）

高度な結果正規化（重大度判定・脆弱性分類の自動化など）は今後のフェーズで拡張します。

## 実機検証状況

このプロジェクトの一貫した方針は、**実際の対象ツール・実際の対象に対して動作確認してから完了とする**ことです（モックデータでのユニットテストだけで済ませない）。以下は全プラグイン・主要機能について、実機検証で確認済みの内容の一覧です。詳細な検証手順・結果は各リンク先を参照してください。

| プラグイン/機能 | 検証対象 | 確認内容 |
| --- | --- | --- |
| `recon`（subfinder） | 実ドメイン（projectdiscovery.io） | 実サブドメイン列挙とJSONL出力のパースを確認 |
| `network`（nmap） | Metasploitable2、OWASP Juice Shop（url種別対象） | 実サービス/バージョン検出を確認。**url種別対象のhostname抽出バグを発見・修正**（[network.py](src/pownforge/plugins/network.py)） |
| `web`（ffuf） | OWASP Juice Shop | `/encryptionkeys`等の実エンドポイント検出を確認 |
| `nuclei` | OWASP Juice Shop | `prometheus-metrics`テンプレートでの実検出→finding化を確認 |
| `kubernetes`（trivy k8s） | `kind`ローカルクラスタ | 実クラスタの誤設定・RBAC不備136件超の検出を確認 |
| `container`（trivy image） | `alpine:3.10` | 実在のCVE（CVE-2021-36159）の検出を確認 |
| `sqlmap` | 自作の意図的に脆弱なFlaskアプリ | boolean-based blind/error-based/UNION queryの検出とDBMS判定を確認 |
| `vulncheck`（nmap NSE） | ローカルTLSサーバー、Metasploitable2 | 許可リスト15本全てを実際のnmapで実行。**hostrule系スクリプト（smb-vuln-ms17-010等）の結果取りこぼしバグを発見・修正**（[vulncheck.py](src/pownforge/plugins/vulncheck.py)） |
| `pownforge result import`/`add-finding`（手動証跡取り込み） | Metasploitable2 | 実スキャン→手動exploit記録→findingの追加→`evidence verify`→ウォークスルー生成までの一気通貫を確認 |
| `Engagement`（横展開の記録） | 実nmapスキャン+手動pivot記録 | Engagement外の対象への記録が拒否されること、正規メンバー間のpivot記録とウォークスルーへの反映を確認 |
| `pownforge lab`（攻撃対象ホストの動的追加） | `tleemcjr/metasploitable2` | **常駐しないラボイメージ向けの`docker run -i`修正**（[lab.py](src/pownforge/core/lab.py)）を実機検証で発見・修正 |
| `Playbook`（複数プラグインの連続実行・条件分岐） | OWASP Juice Shop、CLI/Web UI/Emacsの3経路 | 線形実行・条件分岐(`when`)の両方を実際に確認。Web UIはブラウザでPlaybooks画面からWebSocketライブ進捗まで、EmacsはCLI経由のライブテールまで実機確認。**`process-status`をシンボルのまま`string-trim`に渡すEmacs側の潜在バグ（`pownforge-scan`にも存在）を発見・修正**（[pownforge.el](emacs/pownforge.el)） |

見つかったバグはいずれも実機検証でのみ露見するもので（モックXML/JSONを使うユニットテストだけでは検出できなかった）、発見のたびに再現テストを追加した上で修正しています。詳細な検証記録は [docs/handbook.md §6 プラグイン](docs/handbook.md#6-プラグイン)・[§7 ラボネットワーク](docs/handbook.md#7-ラボネットワーク)・[§12 Target modelとスコープ制御](docs/handbook.md#12-target-modelとスコープ制御) を参照してください。
