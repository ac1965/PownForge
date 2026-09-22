# Emacs連携(`emacs/pownforge.el`)

`pownforge`実行バイナリをそのまま呼び出す薄いEmacs Lispラッパーです。スコープ検証
(`ScopePolicy`)・プラグイン実行(`ScanRunner`)・証跡保存はCLI/Web UIと完全に共通で、
`pownforge.el`側では一切再実装していません(見た目が変わるだけで、認可判定は常に
Python側の同じコードパスを通ります)。

## セットアップ

```elisp
(add-to-list 'load-path "/path/to/PownForge/emacs")
(require 'pownforge)

;; 任意。設定しない場合はpownforge自身の既定値
;; (config/targets.yaml, .pownforge/) が使われる。
(setq pownforge-executable "/path/to/PownForge/.venv/bin/pownforge")
(setq pownforge-config-file "/path/to/PownForge/config/targets.yaml")
(setq pownforge-workdir "/path/to/PownForge/.pownforge")
```

`use-package`を使う場合:

```elisp
(use-package pownforge
  :load-path "/path/to/PownForge/emacs"
  :commands (pownforge-target-list pownforge-scan pownforge-result-list
             pownforge-audit-list pownforge-findings-to-org))
```

## コマンド一覧

| コマンド | 内容 |
| --- | --- |
| `pownforge-target-list` | 登録済み対象を`tabulated-list-mode`で表示。行上で`s`を押すと`pownforge-scan`へ |
| `pownforge-plugin-list` | 利用可能プラグインと外部ツールの有無を表示 |
| `pownforge-scan` | 対象・プラグインを`completing-read`で選択(対象の`allowed_plugins`で候補を絞り込み)、オプションを`key=value key2=value2`形式で入力し、`pownforge scan ... --live`を非同期実行。ツールの出力を1行ずつバッファへライブ表示する(Web UIのWebSocketライブ進捗と同じ`on_line`ストリーミングを、サブプロセスのパイプ越しに使うだけ)。完了後`C-c C-c`で結果を開く |
| `pownforge-result-list` | 過去の実行一覧。`RET`で詳細、`o`でその実行のfindingsをOrgとして挿入 |
| `pownforge-result-show` | 実行の詳細(target/plugin/tool_version/findings)を表示。findingsはseverity降順。行上で`r`を押すと`pownforge result review`でステータス変更 |
| `pownforge-report-generate` | Markdownレポートを生成しファイルを開く |
| `pownforge-audit-list` | `ScopePolicy`が拒否した実行試行の一覧(`tabulated-list-mode`) |
| `pownforge-findings-to-org` | 実行のfindingsをOrgアウトラインとして現在のバッファ(要`org-mode`)のpointに挿入 |
| `pownforge-review-finding-in-org-at-point` | 上記で挿入したOrg見出しの`POWNFORGE_RUN_ID`/`POWNFORGE_FINDING_ID`プロパティから、そのfindingを直接レビュー(`pownforge result review`実行 + TODO状態を追従) |

## Org-mode連携の使い方

`pownforge-findings-to-org`は、findingごとに次のような見出しを挿入します:

```org
** TODO [#A] Exposed admin panel  :medium:tool:
:PROPERTIES:
:POWNFORGE_RUN_ID: run001
:POWNFORGE_FINDING_ID: f1
:END:
found at /admin
```

- severity → Org priority: `critical`/`high` → `#A`、`medium` → `#B`、`low`/`info` → `#C`
- finding.status → TODO キーワード: `needs-review` → `TODO`、`confirmed` → `DONE`、
  `false-positive` → `CANCELLED`

`CANCELLED`をTODOキーワードとして認識させるため、`org-todo-keywords`に含めることを
推奨します(未設定でも見出しのテキスト自体は`CANCELLED`になりますが、Orgの完了状態
として扱われません):

```elisp
(setq org-todo-keywords '((sequence "TODO" "|" "DONE" "CANCELLED")))
```

挿入した見出し上で`pownforge-review-finding-in-org-at-point`を実行すると、新しい
ステータスを`completing-read`で選び、実際に`pownforge result review <run-id>
<finding-id> <status>`を実行したうえで見出しのTODOキーワードを更新します。つまり
Org側での「レビュー」は表示上のラベル変更ではなく、常にCLI経由でスコープ強制済みの
実データ(`.pownforge/runs/*.json`)を書き換えます。

## テスト

```bash
make emacs-test
```

`emacs/tests/pownforge-test.el`(ERT)は`emacs/tests/fixtures/fake-pownforge`という
スタブシェルスクリプトを使い、実際のPython環境やスキャン対象なしにパース処理・
非同期プロセス(ライブスキャン)・Org連携を検証します。出力フォーマットは
`docs/cli-contract.md`および`tests/test_plugins.py`のフィクスチャと揃えてあります。

実機検証: 実際の`pownforge`バイナリ・`nmap`を使い、`pownforge-scan`でlocalhostへの
ライブスキャンがバッファへ逐次表示されること、完了後に`run <id> completed`から
run idが解決されること、`pownforge-result-show`/`pownforge-findings-to-org`が
実際のJSON出力を正しく描画することを確認済み。
