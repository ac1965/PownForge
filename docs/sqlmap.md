# sqlmapプラグイン(`pownforge scan sqlmap`)

`sqlmap`を使い、URL中のパラメータに対するSQLインジェクションを検出・
(オプションで)実際にデータを抽出します。検出された各インジェクション手法は
そのままfinding(`source: "tool"`、severity`critical`、既定`needs-review`)として
`RunRecord.findings`に記録されます。

## 安全設計(重要)

sqlmapは他のプラグイン(nmap/ffuf/nuclei/trivy)と違い、**SQLインジェクションを
足がかりにOSコマンド実行やファイル操作にまでエスカレートできる**ツールです。
これは「対象のURL・パラメータへのSQLi診断」というスコープを大きく逸脱しうるため、
以下の方針で実装しています:

- **`--risk`/`--level`には上限を設けない**。既定は`--risk 1 --level 1`(最も保守的)
  だが、`--option risk=3 --option level=5`のように利用者が明示すれば緩められる。
  これらは「SQLi検出ペイロードの積極度」を変えるだけで、対象を診断すること自体は
  最初から許可されているため
- **`--dump`/`--dump-all`は許可する**。検出だけでなく実際にデータを抽出して見せる
  ことがsqlmapの本来の価値であり、対象は既に`ScopePolicy`で認可済みのため
- **OS/レジストリ/ファイル操作・インタラクティブシェル・設定ファイル読み込みに
  相当するフラグは`--risk`/`--level`の値に関わらず常に拒否する**。理由は
  「SQLi検出の積極度」とは別のカテゴリの機能(スコープをDB診断からホスト・
  場合によってはその先のネットワークにまで逸脱させ得る)であり、緩めるための
  ダイヤルが存在しないため。拒否リスト(`build_command()`が`--option`の
  キーを正規化してチェック、大文字小文字・先頭`-`の有無を問わない):

  ```
  os-shell, os-pwn, os-smbrelay, os-bof, priv-esc, os-cmd,
  reg-read, reg-add, reg-del, reg-key, reg-value, reg-data, reg-type,
  file-read, file-write, file-dest,
  sql-shell, shell, wizard,
  eval, tamper, answers, c, configfile
  ```

  (`c`/`configfile`は追加のsqlmap引数を設定ファイル経由で密輸できてしまうため、
  `answers`は`--batch`が選ぶ保守的な既定回答を上書きできてしまうため、
  それぞれ拒否リストに含めている)

- **`environment=production`のtargetに対する一律禁止は設けない**。
  Target登録時点で`environment=production`は`notes`(認可/契約の参照)必須という
  強制が既に入っており([docs/architecture.md](architecture.md)参照)、これを
  sqlmap実行の認可としてそのまま流用する

## 使い方

```bash
# URL中のパラメータ(例: id)を対象として登録
pownforge target add shop-item --address "https://shop.example/item?id=1" \
  --kind url --type web --allowed-plugins sqlmap

# 検出のみ(既定: risk=1, level=1)
pownforge scan sqlmap --target shop-item --live

# risk/levelを上げる、実際にダンプする
pownforge scan sqlmap --target shop-item \
  --option risk=2 --option level=3 --option dump=true
```

`--option`のキーはそのまま`--{key}`としてsqlmapに渡されます(値が`true`/空文字なら
フラグのみ、それ以外は`--key value`)。`risk`/`level`だけは指定が無い場合に
`1`が既定値として補われます。拒否リストに載っているキーを指定すると
`pownforge scan sqlmap`はsqlmapを実行せずエラー終了します。

## 出力

`normalize()`の`output`には次を含みます:

- `dbms`: 検出されたDBMS名(例: `"SQLite"`)、未検出なら`null`
- `injection_points`: `[{"parameter", "method", "techniques": [{"type", "title", "payload"}, ...]}]`
- `dumped_tables`: `--dump`/`--dump-all`実行時、`{"db.table": [{"col": "value", ...}, ...]}`
  (sqlmapが`--output-dir`配下に書き出すCSVをそのまま読み込み、実行終了後に
  一時ディレクトリごと削除する。永続化される場所は他プラグインと同じく
  `EvidenceStore`が管理する実行結果JSONのみ)

## 実機検証記録

意図的に脆弱なローカルFlaskアプリ(`SELECT ... WHERE id = ` + 生の文字列結合、
sqliteバックエンド)をDockerで用意し、実際の`sqlmap`(1.10.9)で検証した。
`--risk 1 --level 1`のままboolean-based blind/error-based/time-based blind/
UNION queryの4手法が検出され、`pownforge scan sqlmap`実行後の`result show`で
4件のfinding(`severity: critical`、`source: "tool"`、`status: "needs-review"`)
として記録されることを確認。`--option dump=true`では実際に抽出された行が
`output.dumped_tables`にそのまま記録されることも確認。`--option os-shell=true`
指定時にsqlmapを実行せずエラーになることも確認済み。
