# アーキテクチャ

PownForge は、CLI・スコープ検証・プラグイン実行・証跡保存・レポート/分析を明確に分離します。

```text
CLI (Typer)
  │
  ├── ScopePolicy    … 対象の登録・スコープ検証（config/targets.yaml）
  ├── PluginRegistry … 利用可能なプラグインの登録・取得
  ├── ScanRunner     … ポリシー確認 → プラグイン実行 → 証跡保存
  ├── EvidenceStore  … 実行結果（JSON）の保存・読み出し
  ├── reporting      … Markdownレポート生成
  └── ai.OllamaAdapter … ローカルLLM（~/.local/bin/llm 経由）による分析
```

## 設計原則

- **AIに直接スキャンを任せない**: `ai/` はすでに保存された結果を要約・分析するだけで、
  スキャン対象や実行コマンドを決定する権限を持ちません。
- **スコープはコードで強制する**: `pownforge scan` は `config/targets.yaml` に
  登録された対象名でしか実行できません。任意のホスト名・URLを直接引数に取りません。
- **プラグインは実行と正規化のみを担当する**: 証跡の保存形式やファイルパスは
  `evidence/` が一元管理し、プラグインが独自形式で書き込むことはありません。

## プラグインインターフェース

`src/pownforge/plugins/base.py` の `Plugin` 抽象クラスを実装します。

- `check() -> bool`: 必要な外部ツールが利用可能か
- `build_command(target, options) -> list[str]`: 実行するコマンド（検証済みtargetのみを使用）
- `normalize(target, raw_stdout, raw_stderr) -> dict`: 生出力をJSON化可能な形式に変換

## 今後の拡張

- 結果正規化の高度化（nmap XML出力のパース、ffuf JSON出力の構造化）
- Kubernetes/クラウド構成診断プラグイン
- Emacs連携（`pownforge.el`）
