# containerプラグイン(`pownforge scan container`)

`trivy image`を使い、コンテナイメージの脆弱性(Vulnerabilities)・誤設定
(Misconfigurations、`--image-config-scanners misconfig`指定時)・漏洩シークレット
(Secrets、`--image-config-scanners secret`指定時)をまとめて検出します。検出結果は
そのままfinding(`source: "tool"`、既定`needs-review`)として`RunRecord.findings`に
記録されます。実装は[kubernetesプラグイン](kubernetes.md)(`trivy k8s`)と同じ
trivy JSON(`Results[].{Misconfigurations,Vulnerabilities,Secrets}`)を解析するため、
抽出ロジックは`src/pownforge/plugins/_trivy.py`として共通化しています。

## 他のプラグインとの違い

kubernetesプラグイン同様、`Target.address`はhost/URLではなく**コンテナイメージの
参照**(例: `nginx:1.25`、`registry.example.com/app:latest`)として扱います。
`Target.kind`は`host`のままで問題ありません。分類用に`Target.type`へ`container`を
設定できますが、これは表示・分類目的のみで、スキャン許可判定には引き続き
`allowed_plugins`だけが使われます。

対象イメージは、`pownforge`を実行しているマシンのDocker/containerd/podman経由で
(ローカルに無ければpullして)取得されます。現状のDockerランタイムイメージ
(`docker/Dockerfile.runtime`)にはtrivyを含めていないため、通常は開発者のホスト上
(trivyがすでに使える環境)で実行することを想定しています。

## 使い方

```bash
# イメージ参照をそのままaddressとして対象登録
pownforge target add web-app-image --address "myregistry.example.com/web-app:1.4.2" \
  --kind host --type container --allowed-plugins container

# severityで絞り込んでスキャン
pownforge scan container --target web-app-image \
  --option severity=HIGH,CRITICAL --option ignore-unfixed=true
```

`--option`のキー:

| キー | 内容 |
| --- | --- |
| `severity` | `trivy image --severity`にそのまま渡す(例: `HIGH,CRITICAL`。trivyは大文字) |
| `ignore-unfixed` | `true`で`--ignore-unfixed`(修正版が無い脆弱性を除外) |
| `scanners` | `trivy image --scanners`にそのまま渡す(例: `vuln,misconfig,secret`) |

## 実機検証記録

サポート終了済みで既知の脆弱性を含む`alpine:3.10`イメージを対象に、実際の
`trivy`(0.74.0)で検証した。`--severity HIGH,CRITICAL`で実行し、実在のCVE
(`CVE-2021-36159`、apk-toolsのlibfetch経由の境界外読み取り)がそのままfinding
(`severity: critical`、`source: "tool"`、`status: "needs-review"`)として
`pownforge scan container`実行後の`result show`に記録されることを確認済み。
