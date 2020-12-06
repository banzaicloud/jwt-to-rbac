# Install Dex as OpenID conect provider

## Add banzaicoud helm repo
```shell
helm repo add banzaicloud https://kubernetes-charts.banzaicloud.com
helm repo update
```

Downoad the dex.yaml.dist file.
```shell
curl -o dex.yaml https://raw.githubusercontent.com/banzaicloud/jwt-to-rbac/master/docs/dex.yaml.dist
```

Edit the `dex.yaml` file for your needs and deploy Dex via helm.
```shell
helm install dex banzaicloud/dex -f dex.yaml
```
