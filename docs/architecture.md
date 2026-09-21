# アーキテクチャ

PownForge は、CLI・スコープ検証・プラグイン実行・証跡保存・レポート/分析を明確に分離します。

```text
CLI (Typer)
  │
  ├── ScopePolicy    … 対象の登録・スコープ検証（config/targets.yaml）
  ├── PluginRegistry … 利用可能なプラグインの登録・取得
  ├── ScanRunner     … ポリシー確認 → プラグインのbuild_command実行(subprocess) → normalize → 証跡保存
  ├── LabManager     … 隔離Dockerネットワーク上での攻撃対象コンテナの起動・削除・一覧
  ├── EvidenceStore  … 実行結果（JSON）の保存・読み出し
  ├── reporting      … Markdownレポート生成
  └── ai.OllamaAdapter … ローカルLLM（~/.local/bin/llm 経由）による分析
```

## 設計原則

- **AIに直接スキャンを任せない**: `ai/` はすでに保存された結果を要約・分析するだけで、
  スキャン対象や実行コマンドを決定する権限を持ちません。
- **スコープはコードで強制する**: `pownforge scan` は `config/targets.yaml` に
  登録された対象名でしか実行できません。任意のホスト名・URLを直接引数に取りません。
  `pownforge lab add` も最終的に同じ `ScopePolicy.add_target()` を通ります。
- **コマンド組み立てと実行を分離する**: プラグインは `build_command`/`normalize` の
  みを担当し、実際に外部プロセスを起動するのは `ScanRunner`（`LabManager` も同様の
  分離）に一本化しています。証跡の保存形式やファイルパスは `evidence/` が一元管理し、
  プラグインが独自形式で永続化することはありません（中間出力を一時ファイルに書いても
  `normalize` 内で読み込み次第削除します）。

## プラグインインターフェース

`src/pownforge/plugins/base.py` の `Plugin` 抽象クラスを実装します。

- `check() -> bool`: 必要な外部ツールが利用可能か
- `build_command(target, options) -> list[str]`: 実行するコマンド（検証済みtargetのみを使用）
- `normalize(target, raw_stdout, raw_stderr) -> dict`: 生出力をJSON化可能な形式に変換
  （`NetworkPlugin`/`WebPlugin` は現在、nmapのXML/ffufのJSON出力を構造化データに
  変換済み。詳細は [docs/walkthrough.md](walkthrough.md) の実機検証を参照）

## 今後の拡張

- 重大度判定・脆弱性分類の自動化（`Finding`モデルは定義済みだが、現状は常に空リスト）
- `pownforge analyze` の出力が `RunRecord` / レポートに永続化されない点の解消
  （現状は標準出力に表示するのみで、`report generate` の "No findings" 表示は
  analyze実行後も変わらない）
- Kubernetes/クラウド構成診断プラグイン
- Emacs連携（`pownforge.el`）
