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
| **ポリシー違反が証跡に残る** | ❌ **未実装**。`PolicyError`は画面に出すだけで、拒否された試行はどこにも記録されない |

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

- `tool_version`(nmap/ffufのバージョン記録) — ❌ 未実装
- `command`の秘匿処理(認証情報等のマスキング) — ❌ 未実装(現状のプラグインには
  秘匿すべき引数が無いため実害は無いが、将来`identity`系プラグインを追加する際は必須)
- `pownforge evidence verify <run-id>` — ❌ **未実装**。ハッシュは保存しているが、
  それを検証するコマンドが無い

「SHA-256は完全な改ざん防止ではない」という当初の設計上の注意は、実装にもそのまま
当てはまる(同一権限のユーザーが証跡とハッシュを両方書き換えられる)。

### Phase 5: Web/API Security Plugin — 🟡 部分完了、重要な設計要素が未実装

| ツール | 状況 |
| --- | --- |
| ffuf | ✅ 実装済み(`WebPlugin`、オートキャリブレーション`-ac`込み) |
| nuclei | ❌ 未実装 |
| sqlmap | ❌ 未実装 |
| curl/httpx(API確認) | ❌ 未実装(`httpx`は依存関係にあるが未使用) |

**最大のギャップ**: 当初案の「Tool Output → Parser → Candidate Finding →
Manual Verification → Confirmed/False Positive/Needs Review」という検証ワークフローが
無い。実装した`Finding`モデルは`title/severity/detail/source`のみで、
`finding_id`・`evidence_refs`(証跡への参照)・`status`(needs-review等)が無い。
`source: "ai"|"manual"`という区別（AI推定は確定した脆弱性として扱わない）は
当初案の思想を部分的にカバーしているが、「人間が確認してconfirmed/false-positiveに
遷移させる」という状態遷移そのものは実装されていない。

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
より簡素な技術ダンプに近い構成。「検証済み事項」と「未検証事項」を分けて書く、
という思想はPhase 5のFinding.status不在と同様、まだ反映できていない。

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
| 1 | **Finding.status(needs-review/confirmed/false-positive)の導入** | Phase 5/6の核心的なギャップ。これが無いと、AIが見つけたfindingsが「確認待ち」のまま埋もれる。Web UIの閲覧画面にも直結する |
| 2 | **ポリシー違反の証跡化**(拒否された実行試行の記録) | Phase 2の完了条件で唯一未達。セキュリティツールとして「誰が何を試みて拒否されたか」を残せないのは監査上のギャップ |
| 3 | **`pownforge evidence verify`** | ハッシュを保存しているのに検証手段が無い状態を解消 |
| 4 | **Web UIの書き込み系画面(Slice 3)**: Target追加・Lab起動・NewScan+ライブ進捗 | 既に設計・バックエンドは完了しており、フロントエンドのフォーム追加のみ |
| 5 | **tool_versionの記録** | nmap/ffufのバージョンを証跡に残す。トリアージ時に「どのバージョンで検出/未検出だったか」が分かるようにする |
| 6 | **Web/APIプラグインの拡充**(nuclei等) | Phase 5の主要ツールが未着手 |
| 7 | **Target modelのtype/environment拡張** | Kubernetes/実案件プラグインに着手するタイミングで一緒に設計(既存判断を維持) |
| 8 | **Kubernetesプラグイン(Phase 8)、Emacs連携(Phase 9)** | 明示的な依頼があるまで着手しない |

M6(Kubernetes)・M7(Emacs)は当初計画のまま残っており、着手時期は未定です。
