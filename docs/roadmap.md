# ロードマップ: 設計時プランと実装状況の対比

設計当初に提示された「Phase 2〜10」のロードマップ（10フェーズ・M1〜M7マイルストーン）と、
実際にこのリポジトリで実装した内容を照合した記録です。実装確認日: 2026-09-22。

## マイルストーン対比（M1〜M7）

| マイルストーン | 当初の到達点 | 状況 | 補足 |
| --- | --- | --- | --- |
| **M1** | CLI + Target + Plugin Registry | ✅ 完了 | Typer CLI、`ScopePolicy`、`PluginRegistry` |
| **M2** | Network Plugin + Result Store | ✅ 完了 | `NetworkPlugin`(nmap)、`EvidenceStore` |
| **M3** | Evidence + Markdown Report | 🟡 部分完了 | 保存構造・検証コマンドが当初案と異なる（後述） |
| **M4** | Web/API Plugin | 🟡 部分完了 | `WebPlugin`(ffuf)/`NucleiPlugin`(nuclei)/`SqlmapPlugin`(sqlmap)。API専用プラグインは未着手 |
| **M5** | Ollama Analysis | ✅ 完了 | 当初設計とほぼ一致 |
| **M6** | Kubernetes Lab | 🟡 部分完了 | `KubernetesPlugin`(`trivy k8s`)で誤設定/RBAC/イメージ脆弱性検出は実装済み。専用のk8sラボ構成(kube-bench等)は未着手 |
| **M7** | Emacs Integration + SDK | 🟡 部分完了 | `emacs/pownforge.el`でEmacs連携は実装済み(後述)。SDKは`Plugin` ABCのみ |

**当初計画に無かった追加実装**: Web UI(FastAPIバックエンド + React SPA、
ライブ進捗WebSocket、`pownforge lab`による攻撃対象コンテナの動的管理)。
この2つはロードマップ策定後にユーザー要望で追加され、M7の「操作インターフェース」を
Emacsより先にWeb UIで実現した形になっている。Emacs連携自体も後日
(`emacs/pownforge.el`)追加した。

---

## Phase別の詳細

### Phase 1: CLI基盤・Plugin Registry — ✅ 完了

計画通り。`src/pownforge/cli.py`(Typer)、`core/registry.py`(`PluginRegistry`)、
`plugins/base.py`(`Plugin` ABC)。

### Phase 2: Target管理・Scope Policy — 🟡 部分完了

| 完了条件 | 状況 |
| --- | --- |
| 登録されていない対象を実行できない | ✅ `ScopePolicy.authorize()` |
| 許可されていないプラグインを実行できない | ✅ `Target.allowed_plugins` |
| 実行前に対象とポリシーを検証できる | ✅ |
| ポリシー違反が証跡に残る | ✅ **完了**。`ScanRunner`が`PolicyError`を`AuditStore`(`evidence/audit.py`)に記録してから再送出する。`pownforge audit list/show`、`GET /api/audit`、Web UIのAuditページ/Dashboardパネルから確認可能 |

データモデルは当初案（`type`/`environment`/`endpoints`(複数)/`scope.allowed`+`excluded`/
`policy.max_concurrency`）と比べ、`endpoints`/`scope.allowed`+`excluded`/
`policy.max_concurrency`は依然として簡素なまま:

```python
class Target(BaseModel):
    name: str
    kind: TargetKind          # host | url。address形式(実行時にプラグインが使う)
    address: str              # endpoints(複数)ではなく単一
    allowed_plugins: list[str]
    notes: str | None
    type: TargetType | None   # network | web | api | kubernetes（✅ 追加。分類用のみ）
    environment: TargetEnvironment  # ✅ 追加。local-lab(既定)|staging|production
    # excluded, max_concurrency は無い
```

`type`/`environment`は✅**完了**（後述の優先順位リスト参照）。`environment`は
表示用のラベルに留めず、`production`の場合`notes`(認可/契約の参照)が無いと
`ScopePolicy.add_target()`が`PolicyError`を送出するようコードで強制した。
「除外対象」「対象ごとの同時実行数制限」は依然未実装のまま
（具体的な利用者が無いまま拡張するのは時期尚早、という判断を維持）。

### Phase 3: Network Recon Plugin — 🟡 部分完了

| ツール | 状況 |
| --- | --- |
| nmap | ✅ 実装済み(`NetworkPlugin`) |
| dig | ❌ 未実装 |
| curl | ❌ 未実装 |
| tcpdump | ❌ 未実装 |

`--profile safe`のような名前付きプロファイル機構は無く、`--option ports=3000`のような
汎用key=valueオプションのみ。共通結果フォーマットも、当初案の
`{run_id, target, plugin, status, findings, evidence, started_at}`とは異なり、
実装は`RunRecord{run_id, target, plugin, created_at, evidence, output, findings, analysis}`
という形（`status`文字列は無く、成否は`evidence.returncode`で判断）。
タイムアウト・失敗処理は実装済み(`RunnerError`)。

### Phase 4: Evidence・Result Store — 🟡 部分完了(設計が異なる)

当初案は実行ごとに複数ファイル(`manifest.json`/`result.json`/`findings.json`/
`stdout.txt`/`stderr.txt`/`hashes.json`)に分ける構造だったが、実装は
**1実行1JSONファイル**(`.pownforge/runs/{run_id}.json`)に統合する設計にした
（`RunRecord`をまるごとシリアライズ）。中身は当初の記録項目とおおむね対応するが、
以下は未実装:

- `tool_version`(nmap/ffufのバージョン記録) — ✅ **完了**。`Plugin.version_command()`
  (nmapは`nmap --version`、ffufは`ffuf -V`)を`ScanRunner`が実行し、
  `Evidence.tool_version`に保存する。CLI(`result show`/`report generate`)・
  Web API(`GET /api/runs/{id}`)・Web UI(Run detail画面)いずれからも確認可能
- `command`の秘匿処理(認証情報等のマスキング) — ❌ 未実装(現状のプラグインには
  秘匿すべき引数が無いため実害は無いが、将来`identity`系プラグインを追加する際は必須)
- `pownforge evidence verify <run-id>` — ✅ **完了**。保存済み`output`から
  stdout/stderrのSHA-256を再計算し、`evidence.stdout_sha256`/`stderr_sha256`と
  比較する。CLI(`pownforge evidence verify`)・Web API
  (`GET /api/runs/{id}/verify`)・Web UI(Run detail画面の「Verify evidence」
  ボタン)のいずれからも実行可能

「SHA-256は完全な改ざん防止ではない」という当初の設計上の注意は、実装にもそのまま
当てはまる(同一権限のユーザーが証跡とハッシュを両方書き換えられる)。
`evidence verify`はこの限界を前提に、偶発的・部分的な変更の検出に用途を
限定している(CLI/Web双方の出力にその旨を明記)。

### Phase 5: Web/API Security Plugin — 🟡 部分完了(検証ワークフローは追加済み)

| ツール | 状況 |
| --- | --- |
| ffuf | ✅ 実装済み(`WebPlugin`、オートキャリブレーション`-ac`込み) |
| nuclei | ✅ 実装済み(`NucleiPlugin`)。テンプレート単位の検出結果をそのまま
  `Finding`(`source="tool"`、既定`needs-review`)として記録する、当初案の
  検証ワークフローに最も近いプラグイン |
| sqlmap | ✅ 実装済み(`SqlmapPlugin`)。`--risk`/`--level`/`--dump`は自由に使えるが、
  OS/レジストリ/ファイル操作・シェル・設定ファイル読み込みに相当するオプションは
  常に拒否する安全設計(詳細は[docs/sqlmap.md](sqlmap.md))。検出手法ごとに
  `Finding`(`source="tool"`、severity`critical`)として記録 |
| curl/httpx(API確認) | ❌ 未実装(`httpx`は依存関係にあるが未使用) |

当初案の「Tool Output → Parser → Candidate Finding → Manual Verification →
Confirmed/False Positive/Needs Review」という検証ワークフローは
**実装済み**。`Finding`に`finding_id`(自動採番)と`status`
(`needs-review`|`confirmed`|`false-positive`、既定は常に`needs-review`)を追加し、
`pownforge result review <run-id> <finding-id> <status>` / Web UI(Run detail画面の
確認ボタン) / `PATCH /api/runs/{id}/findings/{id}` のいずれからも状態遷移できる。
`evidence_refs`(findingから証跡ファイルへの直接参照)は未実装(現状は1実行1ファイルの
`RunRecord`にfindingsが内包されているため、参照が無くても同じJSON内で辿れる)。

### Phase 6: Reporting Engine — 🟡 部分完了

| 出力形式 | 状況 |
| --- | --- |
| Markdown | ✅ 実装済み(`reporting/markdown.py`) |
| JSON | ✅ (`result show`/`GET /api/runs/{id}`がJSONを返す) |
| HTML | ✅ 実装済み(`reporting/html.py`)。Markdown→HTML変換ライブラリは使わず、
  同じ構造を直接HTML化する自己完結ページ(インラインCSS)。severity配色は
  Web UIの`.severity-*.badge`と共通 |
| PDF | ❌ 未実装 |

`report generate --format markdown|html`(既定markdown)、Web APIは
`GET /runs/{id}/report?format=html`で選択可能。レポート構成も
当初案の9セクション(概要・対象範囲・実施日時・使用ツールバージョン・診断結果・
検証済み事項・未検証事項・推奨対応・証跡一覧)に対し、実装は
Target/Plugin/Created/Return code/Command/ハッシュ/Findings/AI分析/Raw outputという
より簡素な技術ダンプに近い構成。ただし「検証済み事項」と「未検証事項」を分けて書く、
という思想は、Finding.statusの導入によりFindingsセクション内で
「確認済み/要確認/誤検知として却下」の見出し分けとして反映済み。使用ツール
バージョン・推奨対応・証跡一覧といった残りのセクションは未実装のまま。

### Phase 7: Ollama AI Analysis — ✅ ほぼ計画通り

当初案のアーキテクチャ(`PownForge → Analysis Adapter → ~/.local/bin/llm → Ollama`)、
CLI(`pownforge analyze <run-id> [--model ...]`)とも実装が一致。「要約」「分類」は
実装済み(`analysis`文字列 + 構造化`findings`)。AIの制約(無制限の外部アクセス禁止・
スコープ自動拡張禁止・破壊的操作禁止・人間の確認なしに確定させない)も、
`source="ai"`かつ常にレポート上で明示する設計により実質的に守られている。
このフェーズが当初案に最も近い形で実現できている。

### Phase 8: Kubernetes Security Lab — 🟡 部分完了

`trivy k8s`によるクラスタの誤設定/RBAC/イメージ脆弱性/シークレット検出を
`KubernetesPlugin`(`pownforge scan kubernetes`)として実装済み。`Target.address`に
kubeconfigのcontext名を格納する方式とし、`Target`/`TargetKind`スキーマの拡張は
見送った(既存判断を維持)。実機の`kind`クラスタで258件のfinding(実在CVE・
K8s設定不備を含む)を検出し、CLI/Web UI双方での表示を確認済み(詳細は
[docs/kubernetes.md](kubernetes.md))。kube-bench連携・専用k8sラボ構成
(`pownforge lab`からのクラスタ起動)は未着手。

### Phase 9: Emacs Integration — ✅ 完了

`emacs/pownforge.el`として実装。`pownforge`実行バイナリをサブプロセスとして
呼ぶだけの薄いラッパーで、スコープ検証・実行ロジックはCLI/Web UIと完全に共通
(再実装しない)。

- 対象/プラグイン一覧を`tabulated-list-mode`で表示(`pownforge-target-list`/
  `pownforge-plugin-list`)
- `pownforge-scan`: target/pluginを`completing-read`で選択、`pownforge scan
  ... --live`を非同期実行しツール出力をバッファへ逐次表示。`--live`は今回
  CLI側に追加したオプションで、既存の`ScanRunner.run(on_line=...)`
  (Web UIのWebSocketライブ進捗が使っているのと同じコールバック)をCLIからも
  使えるようにしただけ
- `pownforge-result-show`: findingをseverity降順で表示し、その場で
  `pownforge result review`によるステータス変更が可能
- `pownforge-findings-to-org`/`pownforge-review-finding-in-org-at-point`:
  Org-mode連携。findingをOrg見出し(severity→priority、status→TODO
  キーワード)として挿入し、見出し上からのレビューが実データ
  (`pownforge result review`)を書き換える

`pownforge.el`・Org-mode連携ともに実装済み。テストは`emacs/tests/`のERT
(`make emacs-test`、スタブCLI経由で16件)、実機では実際の`pownforge`
バイナリ+`nmap`によるライブスキャン・結果表示・Org変換を確認済み
(詳細は[docs/emacs.md](emacs.md))。

### Phase 10: Plugin SDK・運用高度化 — 🟡 部分完了

`Plugin` ABC(`check`/`build_command`/`normalize`)に加え、宣言的な
`expected_kind`/`kind_hint`(このプラグインが前提とする`Target.kind`と、
それを検証する`require_kind()`)を追加した。以前は`SqlmapPlugin`だけが
手書きでkind検証していたが、6プラグイン全てが同じ仕組みで宣言・検証するよう
統一(`pownforge plugin info`/`GET /api/plugins`で`expected_kind`を確認可能)。
`tests/plugin_contract.py::assert_plugin_contract()`で全プラグイン共通の
ABC契約(name/version/description/required_tool/check/version_command の型)を
一括検証するテストヘルパーも追加した。当初案の
`PluginMetadata{name, version, description, capabilities}`のような正式な
SDKパッケージ化・入力出力の型スキーマ(`options`/`normalize()`の戻り値)までは
未実装のまま。候補プラグインのうち`kubernetes`(`trivy k8s`)・`container`
(`trivy image`)は実装済み(Phase 8/本ページの優先順位リスト参照)、`identity`は
未実装。

---

## 今後のロードマップ(優先順位案)

前フェーズまでの実装で分かった「先に直すと後が楽になる」順に並べています。

| 優先度 | 項目 | 理由 |
| --- | --- | --- |
| ~~1~~ | ~~Finding.status(needs-review/confirmed/false-positive)の導入~~ | ✅ **完了**。`finding_id`/`status`をFindingに追加し、`pownforge result review`・Web UI(Run detailの確認ボタン)・`PATCH /api/runs/{id}/findings/{id}`から状態遷移可能に。レポートも検証状態別に見出しを分けて出力するよう変更 |
| ~~2~~ | ~~ポリシー違反の証跡化~~(拒否された実行試行の記録) | ✅ **完了**。`ScanRunner`が`PolicyError`を`AuditStore`に記録。`pownforge audit list/show`・`GET /api/audit`・Web UIのAuditページ/Dashboardパネルから確認可能 |
| ~~3~~ | ~~`pownforge evidence verify`~~ | ✅ **完了**。CLI/Web API/Web UIから、保存済み`output`と証跡ハッシュの一致を確認できる |
| ~~4~~ | ~~Web UIの書き込み系画面(Slice 3)~~: Target追加・Lab起動・NewScan+ライブ進捗 | ✅ **完了**。Targets/Labページに追加・削除フォーム、New Scan(target/plugin/options選択)→Scan live(WebSocketライブテール)→Run detailへの自動遷移まで実装。実機(Docker)でtarget追加→lab起動(alpine)→対象自動登録→スキャン実行→ライブ出力→Run detail遷移を確認済み |
| ~~5~~ | ~~tool_versionの記録~~ | ✅ **完了**。`Plugin.version_command()`をScanRunnerが実行し`Evidence.tool_version`に保存。CLI/Web API/Web UIから確認可能 |
| ~~1~~ | ~~Web/APIプラグインの拡充~~(nuclei) | ✅ **完了**。`NucleiPlugin`を追加(`pownforge scan nuclei`)。JSONL出力を構造化し、テンプレート単位の検出をそのまま`Finding`として記録する`_findings`規約を`Plugin.normalize()`に追加(既存プラグインは無変更で影響なし)。sqlmapは安全上の設計判断が必要なため引き続き未着手 |
| ~~2~~ | ~~Kubernetesプラグイン~~(Phase 8) | ✅ **完了**。`trivy k8s`を使う`KubernetesPlugin`を追加(`pownforge scan kubernetes`)。`Target.address`にkubeconfigのcontext名を格納する方式とし、Target modelのschema拡張(type/environment)は別項目として後追いした。既存の`_findings`規約をそのまま再利用し、実機`kind`クラスタで検証済み |
| ~~3~~ | ~~Target modelのtype/environment拡張~~ | ✅ **完了**。`type`(network/web/api/kubernetes、分類用のみ)と`environment`(local-lab/staging/production)を`Target`に追加。`environment=production`は`notes`(認可/契約の参照)必須を`ScopePolicy.add_target()`でコード強制。CLI(`--type`/`--environment`)・Web API(Targetモデルにそのまま含まれる)・Web UI(Targetsページのフォーム/一覧)いずれからも設定・確認可能 |
| ~~4~~ | ~~Emacs連携~~(Phase 9) | ✅ **完了**。`emacs/pownforge.el`を追加。`pownforge`実行バイナリをサブプロセスとして呼ぶだけの薄いラッパーで、対象/プラグイン一覧・`--live`によるライブスキャン・finding review・Org-mode連携(findings→Orgアウトライン、見出しからのreview)をカバー。副産物としてCLIに`--live`オプションを追加し、Web UIのWebSocketライブ進捗と同じ`ScanRunner.run(on_line=...)`をCLIからも使えるようにした |
| ~~5~~ | ~~sqlmapプラグイン~~(Phase 5) | ✅ **完了**。`SqlmapPlugin`を追加(`pownforge scan sqlmap`)。安全設計は「`--risk`/`--level`/`--dump`は自由に使える(既定は最も保守的なrisk 1/level 1)、OS/レジストリ/ファイル操作・シェル・設定ファイル読み込みに相当するオプションは常に拒否」という方針で確定(ユーザーと協議のうえ決定)。既存の`_findings`規約を再利用し、意図的に脆弱なローカルアプリ+実機`sqlmap`で検証済み |
| ~~6~~ | ~~containerプラグイン~~(Phase 10) | ✅ **完了**。`trivy image`を使う`ContainerPlugin`を追加(`pownforge scan container`)。`KubernetesPlugin`と同じtrivy JSON形状を扱うため、finding抽出ロジックを`plugins/_trivy.py`に共通化(`KubernetesPlugin`側もこの共通関数を使うようリファクタ、既存テスト・出力形式は無変更)。`Target.address`にイメージ参照を格納する方式とし、`TargetType`に`container`を追加。実機(`alpine:3.10`)で実在のCVE検出を確認済み |
| ~~1~~ | ~~コマンド秘匿処理~~(Evidence.commandのマスキング) | ✅ **完了**。`core/secrets.py::mask_command()`が`--token`/`--password`/`--cookie`等それらしい名前のフラグの値を`***`に置換したコピーを`Evidence.command`に格納する(実行自体はマスク前の引数のまま、`ScanRunner`内の1箇所のみ変更)。今はどのプラグインも該当しないため実害は無いが、将来認証情報を扱うプラグインを追加した際の漏洩を防ぐための予防的実装 |
| ~~2~~ | ~~HTMLレポート出力~~(Phase 6) | ✅ **完了**。新規`reporting/html.py`(Markdown→HTML変換ライブラリは使わず直接HTML化、severity配色はWeb UIの`.severity-*.badge`と共通)。`pownforge report generate --format html`・`GET /runs/{id}/report?format=html`から生成可能 |
| ~~3~~ | ~~Plugin SDKの正式化~~(Phase 10) | ✅ **完了**(部分)。`Plugin`ABCに`expected_kind`/`kind_hint`/`require_kind()`を追加し、6プラグイン全てが前提とする`Target.kind`を宣言・検証するよう統一(以前は`SqlmapPlugin`のみ手書きで検証)。`tests/plugin_contract.py`で全プラグイン共通のABC契約を一括テスト。`PluginMetadata`のフル形式・`options`/`normalize()`の型スキーマ化までは引き続き未実装 |

これでPhase 2〜10は全て完了/部分完了。M6(Kubernetes Lab)は`KubernetesPlugin`
により部分完了(専用ラボ構成は未着手)、Phase 5のAPI専用プラグイン(curl/httpx)・
Phase 10のidentityプラグイン・SDKの完全な型スキーマ化など、各Phaseの残る
未実装細目は上記の詳細を参照。
