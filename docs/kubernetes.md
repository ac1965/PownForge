# Kubernetesプラグイン(`pownforge scan kubernetes`)

`trivy k8s`を使い、クラスタの誤設定(Misconfigurations)・RBAC・
コンテナイメージの脆弱性(Vulnerabilities)・漏洩シークレット(Secrets)を
まとめて検出します。検出結果はそのままfinding(`source: "tool"`、既定
`needs-review`)として`RunRecord.findings`に記録されます。

## 他のプラグインとの違い(重要)

`network`/`web`/`nuclei`プラグインは`Target.address`をホスト名・URLとして
扱いますが、**kubernetesプラグインは`Target.address`をkubeconfigの
context名として扱います**(`kind get clusters`や`kubectl config
get-contexts`で確認できる文字列、例: `kind-pownforge-lab`)。
`Target.kind`は`host`のままで問題ありません(スキーマ上の新しい種別は
追加していません)。

対象のクラスタへは、`pownforge`を実行しているマシンの`~/.kube/config`
経由で到達できる必要があります。`pownforge scan network/web/nuclei`が
隔離Dockerネットワーク上のコンテナを相手にするのとは異なり、
kubernetesプラグインは通常、開発者のホスト上で(kubectl/trivyがすでに
使える環境で)実行することを想定しています。現状のDockerランタイム
イメージ(`docker/Dockerfile.runtime`)にはtrivy/kubectlを含めていません。

## 使い方

```bash
# kubeconfigのcontext名をそのままaddressとして対象登録
pownforge target add kind-lab --address kind-pownforge-lab --kind host \
  --allowed-plugins kubernetes

# namespaceとseverityで絞り込んでスキャン
pownforge scan kubernetes --target kind-lab \
  --option namespaces=kube-system \
  --option severity=MEDIUM,HIGH,CRITICAL
```

`--option`のキー:

| キー | 内容 |
| --- | --- |
| `namespaces` | `trivy k8s --include-namespaces`にそのまま渡す(comma区切り) |
| `severity` | `trivy k8s --severity`にそのまま渡す(例: `HIGH,CRITICAL`。trivyは大文字) |

## 実機検証記録

`kind`でローカルクラスタ(`kind create cluster --name pownforge-lab`)を
作成し、Homebrewでインストールしたtrivy(0.74.0)を使って実際にスキャンを
実行した。`kube-system`namespaceだけでも258件のfinding
(critical 2 / high 134 / medium 122)が検出され、実在のCVE
(例: `CVE-2026-31789` OpenSSLのヒープバッファオーバーフロー)や
Kubernetesの設定不備(`KSV-0009` hostNetwork有効化、`KSV-0014`
読み取り専用でないルートファイルシステム等)がそのままfindingとして
記録され、CLI(`result show`/`report generate`)・Web UIの両方で
確認できることを確認済み。
