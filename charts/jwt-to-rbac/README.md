# JWT-to-RBAC helm chart

Helm chart for [JWT-to-RBAC](https://github.com/banzaicloud/jwt-to-rbac) that lets you automatically generate RBAC resources based on JWT token.

## Installing the Chart

```bash
$ helm repo add banzaicloud-stable http://kubernetes-charts.banzaicloud.com/branch/master
$ helm repo update
```

Deploying jwt-to-rbac:

```bash
$ helm install --name <name> --set config.tokenhandler.oidc.clientID=<client-id> --set config.tokenhandler.oidc.issuerURL=<http://dex-url/dex>
```

## Configuration

The following table lists configurable parameters of the `jwt-to-rbac` chart and their default values.

|               Parameter             |                Description                  |                  Default                 |
| ----------------------------------- | ------------------------------------------- | -----------------------------------------|
|image.repository                     |jwt-to-rbac image                            |banzaicloud/jwt-to-rbac                   |
|image.tag                            |image tag                                    |0.2.0                                     |
|image.pullPolicy                     |image pull policy                            |IfNotPresent                              |
|port.name                            |port name                                    |http                                      |
|port.containerPort                   |port port                                    |5555                                      |
|post.protocol                        |port protocol                                |TCP                                       |
|service.type                         |service type                                 |ClusterIP                                 |
|service.port                         |service port                                 |5555                                      |
|configDir                            |jwt-to-rbac config directory                 |/etc/jwt-to-rbac                          |
|config.app.addr                      |jwt-to-rbac listen address                   |":5555"                                   |
|config.log.level                     |jwt-to-rbac log level                        |"4"                                       |
|config.log.format                    |jwt-to-rbac log format                       |"json"                                    |
|config.log.noColor                   |jwt-to-rbac log noColor                      |true                                      |
|config.tokenhandler.caCertPath       |CA cert for Oidc used self-signed cert       |""                                        |
|config.tokenhandler.insecure         |Turn off cert verification                   |false                                     |
|config.tokenhandler.oidc.clientID    |client ID for Oidc                           |""                                        |
|config.tokenhandler.oidc.issuerURL   |Oidc url                                     |""                                        |
|config.rbachandler.githubOrg         |specified github organization                |""                                        |
|config.rbachandler.customGroups      |custom group mapping, more details in [JWT-to-RBAC](https://github.com/banzaicloud/jwt-to-rbac)|[]|
|config.rbachandler.tokenTTL          |TTL of the generated tokens                  |"24h"|
|config.rbachandler.enableCreateSAToken |flag for enabling create token api endpoint|false|
|imagePullSecrets                     |image pull credentials (k8s notation) [doc](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry)|[]|