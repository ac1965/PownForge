# ロードマップ: 設計時プランと実装状況の対比

設計当初に提示された「Phase 2〜10」のロードマップ（10フェーズ・M1〜M7マイルストーン）と、
実際にこのリポジトリで実装した内容を照合した記録です。実装確認日: 2026-09-22。

## マイルストーン対比（M1〜M7）

| マイルストーン | 当初の到達点 | 状況 | 補足 |
| --- | --- | --- | --- |
| **M1** | CLI + Target + Plugin Registry | ✅ 完了 | Typer CLI、`ScopePolicy`、`PluginRegistry` |
| **M2** | Network Plugin + Result Store | ✅ 完了 | `NetworkPlugin`(nmap)、`EvidenceStore` |
| **M3** | Evidence + Markdown Report | 🟡 部分完了 | 保存構造・検証コマンドが当初案と異なる（後述） |
| **M4** | Web/API Plugin | 🟡 部分完了 | `WebPlugin`(ffuf)のみ。nuclei/sqlmap/API専用プラグインは未着手 |
| **M5** | Ollama Analysis | ✅ 完了 | 当初設計とほぼ一致 |
| **M6** | Kubernetes Lab | ❌ 未着手 | |
| **M7** | Emacs Integration + SDK | ❌ 未着手 | Emacs連携は未着手。SDKは`Plugin` ABCのみ |

**当初計画に無かった追加実装**: Web UI(FastAPIバックエンド + React SPA、
ライブ進捗WebSocket、`pownforge lab`による攻撃対象コンテナの動的管理)。
この2つはロードマップ策定後にユーザー要望で追加され、M7の「操作インターフェース」を
Emacsではなく先にWeb UIで実現した形になっている。

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
`policy.max_concurrency`）よりかなり簡素:

```python
class Target(BaseModel):
    name: str
    kind: TargetKind        # host | url のみ。type(web/api/k8s)ではない
    address: str            # endpoints(複数)ではなく単一
    allowed_plugins: list[str]
    notes: str | None
    # environment, excluded, max_concurrency は無い
```

「環境区分(local-lab/staging/production)」「除外対象」「対象ごとの同時実行数制限」は
未実装。以前の検討で「具体的な利用者(k8s/実案件プラグイン)が無いまま拡張するのは
時期尚早」として意図的に保留した部分。

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
| nuclei | ❌ 未実装 |
| sqlmap | ❌ 未実装 |
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
| HTML | ❌ 未実装 |
| PDF | ❌ 未実装 |

`--format`フラグ自体が無く、`report generate`は常にMarkdown固定。レポート構成も
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

### Phase 8: Kubernetes Security Lab — ❌ 未着手

kube-bench/Trivy連携、k8sラボ構成、いずれも未着手。

### Phase 9: Emacs Integration — ❌ 未着手(方針転換)

`pownforge.el`・Org-mode連携ともに未着手。代わりに、ユーザーの別要望により
**Web UI(FastAPI + React)** を先に実装した。「見える化」というPhase 9の目的自体は
Web UIがある程度代替しているが、Emacs/Org-modeからの操作という当初案そのものは
未実装のまま。

### Phase 10: Plugin SDK・運用高度化 — 🟡 部分完了

`Plugin` ABC(`check`/`build_command`/`normalize`)は実装済みだが、当初案の
`PluginMetadata{name, version, description, capabilities}`のような正式なSDKパッケージ・
入力出力スキーマの明文化・プラグイン用テストインターフェースは無い。候補プラグイン
(`container`/`kubernetes`/`identity`)は未実装。

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
| 1 | **Web/APIプラグインの拡充**(nuclei等) | Phase 5の主要ツールが未着手 |
| 2 | **Target modelのtype/environment拡張** | Kubernetes/実案件プラグインに着手するタイミングで一緒に設計(既存判断を維持) |
| 3 | **Kubernetesプラグイン(Phase 8)、Emacs連携(Phase 9)** | 明示的な依頼があるまで着手しない |

M6(Kubernetes)・M7(Emacs)は当初計画のまま残っており、着手時期は未定です。
