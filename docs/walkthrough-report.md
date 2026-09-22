# ウォークスルー機能(`pownforge walkthrough generate`)

> **注意**: このファイルは複数runをまたぐ物語調ウォークスルー*機能*のドキュメントです。
> [docs/walkthrough.md](walkthrough.md)(Juice Shopに対する手作業の実機検証記録)とは別物です。

複数のスキャン実行(run)をまたいで、「まず`network`でポート発見→`web`で
エンドポイント発見→`nuclei`で脆弱性確認」のような一連の流れを、AIに
接続ナラティブとして書かせる機能です。`pownforge analyze`と同じ
`OllamaAdapter`(ローカルLLM経由)を使いますが、**どのrunのfindings/analysis
も一切書き換えません**(読み取り専用)。生成されるナラティブはあくまで新しい
一時的なレポートファイルであり、個々のrunの検証状態はこれまで通りCLI/Web UI
で別途管理されます。

## 安全上の設計

- プロンプトには各runの`target`/`plugin`/`created_at`/`findings`
  (title/severity/status/source)だけを渡し、生の`raw_stdout`は渡しません
  (プロンプト長を抑える、tool出力経由のプロンプトインジェクションを避ける)
- プロンプトは「`status`が`confirmed`のfinding以外は確定した脆弱性として
  断定しない」「`needs-review`のfindingは未検証と明記する」よう明示的に
  指示します
- 生成されたナラティブは常に「AI生成・要確認」という注記付きで表示され、
  各runの詳細セクション(findingの検証状態を含む)とセットで提示されます

## AIの提案(Suggestion)

ナラティブに加えて、「次に試すべきこと」をAIが構造化された提案として
出します。`Finding`とは完全に別のモデル(`core/models.py::Suggestion`:
`title`/`plugin`/`rationale`のみ、`status`なし)で、検証ワークフローの
対象ではなく、**どのRunRecordにも永続化されません**(walkthrough自体が
生成する度に使い捨てで作られる一時的な出力)。

「AIに直接スキャンを任せない」という原則は変わりません。提案の`plugin`は
AIの自由記述であり(レジストリとの突き合わせは行いません)、実際に
そのプラグインを実行するかどうかは常に人間が改めて`pownforge scan <plugin>`
を呼ぶ必要があります。提案はレポート上・Web UI上どちらも
「これらはAIによる提案です。実行するかどうかは人間が判断してください。」
という注記付きで表示されます。

LLMへのプロンプトは`{"narrative": "...", "suggestions": [{"title": "...",
"plugin": "...", "rationale": "..."}]}`という単一のJSONオブジェクトを
要求します(`pownforge analyze`と同じ「JSON1個を要求し、パース失敗時は
全文をnarrativeとして扱いsuggestionsは空にする」フォールバック方式)。
モデルがJSON指示に従わない場合でも、応答全文が引き続きナラティブとして
表示されるためレポート自体は壊れません。

## 使い方

### CLI

```bash
# 明示的にrun idを指定順で含める
pownforge walkthrough generate <run-id-1> <run-id-2> --format html

# targetの全runを時系列(古い順)で含める
pownforge walkthrough generate --target <name> --model qwen3:14b
```

`<run-id...>`と`--target`はどちらか一方だけを指定します。`--model`は
`pownforge analyze`と同じくOllamaモデル名(省略時は`llm`のデフォルト)。
出力先は`.pownforge/reports/walkthrough-<最初のrun-id>.{md,html}`。

### Web API

```
POST /api/walkthroughs
{"run_ids": ["<id1>", "<id2>"], "format": "html"}
# または
{"target": "<name>", "model": "qwen3:14b", "format": "markdown"}
```

応答は`{"markdown": "...", "suggestions": [...]}`または
`{"html": "...", "suggestions": [...]}`(`suggestions`はMarkdown/HTML本文にも
含まれるが、Web UIが専用セクションとして描画できるよう構造化データとしても
返す)。run_ids/targetが両方/どちらも無い場合は400、LLM呼び出し失敗時は502。

### Web UI

`Walkthrough`ページ(`/walkthrough/new`)。runの一覧からチェックボックスで
含めるrunを選ぶか(1件もチェックしなければ)targetのドロップダウンから選び、
model/formatを指定して生成します。「AIの提案」は独立したセクションとして
一覧表示され(markdown/htmlの本文をパースし直す必要は無い)、HTML形式は
iframeでプレビューでき、ダウンロードボタンでファイルとして保存できます。

### Emacs

`pownforge-walkthrough-generate`。run idを1件ずつ`completing-read`で
追加していき(空欄で終了)、1件も追加しなければ代わりにtargetを選びます。
生成後は自動でファイルを開きます。詳細は[docs/emacs.md](emacs.md)。

## 実機検証記録

実際に`nmap`で2回スキャンした`network`プラグインのrunを2件用意し、
ローカルOllama(`qwen3:14b`、`llm-ollama`プラグイン経由)で実際にナラティブを
生成した。生成前後で元のrun JSONファイルのMD5ハッシュが完全に一致することを
確認し、非破壊であることを実地検証済み。CLI・Web API(`TestClient`ではなく
実際に`pownforge web serve`を起動)・Web UI(ブラウザで実際にrunを選択して
生成、iframeプレビュー確認)・Emacs(実バイナリ経由でrun id 2件を対話的に
選択し、生成→ファイルオープンまで確認)の4経路すべてで実際に動作することを
確認した。

AIの提案についても、実際に`network`(findingsなし)→`web`(ffufが`/admin`を
発見、`medium`/`needs-review`のfinding)という2runを用意しローカルOllamaで
生成したところ、実際にその finding を踏まえた具体的な提案(要約:
「/adminエンドポイントへの認証が無いことを手動で確認すべき」)がJSONとして
正しくパースされ、CLI生成のHTML・Web UIの専用セクション双方に表示される
ことを確認した。
