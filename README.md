# jwt-to-rbac

JWT-to-RBAC lets you automatically generate RBAC resources based on JWT.

### Requirements:
Configured Dex server which issued used JWT.
If you want to issue tokens with Dex you have to configure it with LDAP connector.
You can use Banzaicloud's [Dex chart](https://github.com/banzaicloud/banzai-charts/tree/master/dex).
If you need LDAP server as well, you can [deploy with docker](https://github.com/osixia/docker-openldap) 

### Build jwt-to-rbac docker image:
```shell
make docker
```

### Deploy resources:
```shell
kubectl create -f deploy/configmap.yaml
kubectl create -f deploy/deployment.yaml
kubectl create -f deploy/service.yaml
# port-forward locally
kubectl port-forward svc/jwt-to-rbac 5555
```
### Create resources using cURL 
```shell
# post JWT
curl --request POST \
  --url http://localhost:5555 \
  --header ': ' \
  --header 'Content-Type: application/json' \
  --header 'cache-control: no-cache' \
  --data '{\n"token": "jwt.toke.data"\n}'

# get generated resources
curl --request GET \
  --url http://localhost:5555/list \
  --header 'cache-control: no-cache'

# get tokens for generated ServiceAccount
curl --request GET \
  --url http://localhost:5555/secret/janedoe-example-com \
  --header 'cache-control: no-cache' \

# delete generated ServiceAccount anits ClusterRoleBindings
curl --request DELETE \
  --url http://localhost:5555/remove/janedoe-example-com \
  --header 'cache-control: no-cache'
```

### Example JWT issued by Dex:
```json
{
  "iss": "http://dex-service/dex",
  "sub": "CiNjbj1qYW5lLG91PVBlb3BsZSxkYz1leGFtcGxlLGRjPW9yZxIEbGRhcA",
  "aud": "example-app",
  "exp": 1549547733,
  "iat": 1549461333,
  "at_hash": "gKh0RG0NZ4CMUo6-g6UpOg",
  "email": "janedoe@example.com",
  "email_verified": true,
  "groups": [
    "admins",
    "developers"
  ],
  "name": "jane",
  "federated_claims": {
    "connector_id": "ldap",
    "user_id": "cn=jane,ou=People,dc=example,dc=org"
  }
}
```

### Example configuration:

```yaml
dex:
  clientID: example-auth-app-id
  issuerURL: "http://dex-service/dex"

server:
  port: 5555

kubeConfig: ""

log:
  level: 4
  format: "json"
  noColor: true

customGroups:
- groupName: developers
  customRules:
  - verbs: [ "get", "list" ]
    resources: [ "deployments", "replicasets", "pods" ]
    apiGroups: [ "", "extensions", "apps" ]
```

