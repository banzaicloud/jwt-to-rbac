# jwt-to-rbac

JWT-to-RBAC lets you automatically generate RBAC resources based on JWT.

### Requirements:
Configured Dex server which issued used JWT.
If you want to issue tokens with Dex you have to configure it with LDAP connector.
You can use Banzaicloud's [Dex chart](https://github.com/banzaicloud/banzai-charts/tree/master/dex).
If you need LDAP server as well, you can [deploy with docker](https://github.com/osixia/docker-openldap) 

### jwt-to-rbac Flow:

1. User or an authentication App has id_token (JWT)
2. POST id_token to jwt-to-rbac App
3. jwt-to-rbac validate id_token with Dex
4. jwt-to-rbac extract usename, groups and so on from token
5. jwt-to-rba call APIserver to crate `ServiceAccount`, `ClusterRoles` and `ClusterRoleBindings`
6. User or an anutheticatin app getting K8s `service account token` trough jwt-to-rbac
8. User authenticate on K8s using `service account token`

**The id_token issued by Dex has a following content:**
```json
{
  "iss": "http://dex/dex",
  "sub": "CiNjbj1qYW5lLG91PVBlb3BsZSxkYz1leGFtcGxlLGRjPW9yZxIEbGRhcA",
  "aud": "example-app",
  "exp": 1549661603,
  "iat": 1549575203,
  "at_hash": "_L5EkeNocRsG7iuUG-pPpQ",
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

After jwt-to-rbac extract information from token, create `ServiceAccount` and `ClusterRoleBinding` using one of default K8s `ClusterRole` as `roleRef` or generate one defined in configuration if it does't exist.

### Default K8s ClusterRoles used by `jwt-to-rbac`

Not all cases create a new `ClusterRole`, for example if a user is member of admin group, don't create this `ClusterRole` because K8s has by default.

Default ClusterRole | Description 
--------------------|------------
cluster-admin       | Allows super-user access to perform any action on any resource.
admin               | Allows admin access, intended to be granted within a namespace using a RoleBinding.
edit                | Allows read/write access to most objects in a namespace.
view                | Allows read-only access to see most objects in a namespace.

### jwt-to-rbac crate custom `ClusterRole` defined in config

Most of cases there are different LDAP groups, so custo groups are configurable with them rules.

```toml
[[rbachandler.customGroups]]
groupName = "developers"
[[rbachandler.customGroups.customRules]]
verbs = [
  "get",
  "list"
]
resources = [
  "deployments",
  "replicasets",
  "pods"
]
apiGroups = [
  "",
  "extensions",
  "apps"
]
```

### Deploy jwt-to-rbac to Kubernetes

After you cloning the [github repository](https://github.com/banzaicloud/jwt-to-rbac) you compile a code and make a `docker image` with one command.
```shell
make docker
```

If you are using docker-for-desktop or minikube, you'll be able to deploy it using locally built image.
```shell
kubectl create -f deploy/rbac.yaml
kubectl create -f deploy/configmap.yaml
kubectl create -f deploy/deployment.yaml
kubectl create -f deploy/service.yaml
# port-forward locally
kubectl port-forward svc/jwt-to-rbac 5555
```

### Commincate with jwt-to-rbac
**POST id_token issued by Dex to API**
```shell
curl --request POST \
  --url http://localhost:5555/ \
  --header 'Content-Type: application/json' \
  --data '{\n	"token": "example.jwt.token"\n}'

# response:
{
    "Email": "janedoe@example.com",
    "Groups": [
        "admins",
        "developers"
    ],
    "FederatedClaimas": {
        "connector_id": "ldap",
        "user_id": "cn=jane,ou=People,dc=example,dc=org"
    }
}
```

**Listing created K8s resources:**
```shell
curl --request GET \
  --url http://localhost:5555/list \
  --header 'Content-Type: application/json'

#response:
{
    "sa_list": [
        "janedoe-example-com"
    ],
    "crole_list": [
        "developers-from-jwt"
    ],
    "crolebind_list": [
        "janedoe-example-com-admin-binding",
        "janedoe-example-com-developers-from-jwt-binding"
    ]
}
```

**GET K8s token of `ServiceAccount`**
```shell
curl --request GET \
  --url http://localhost:5555/secret/janedoe-example-com \
  --header 'Content-Type: application/json'

# response:
[
    {
        "name": "janedoe-example-com-token-m4gbj",
        "data": {
            "ca.crt": "example-ca-cer-base64",
            "namespace": "ZGVmYXVsdA==",
            "token": "example-k8s-sa-token-base64"
        }
    }
]
```

Now you have a base64 encoded `Service account token`.

### Accessing with serviceaccount token 

You can use `Service account token` from command line:
```shell
kubectl --token $TOKEN_TEST --server $APISERVER get po
```

Or create `kubectl` context with it:
```shell
export TOKEN=$(echo "example-k8s-sa-token-base64" | base64 -D)
kubectl config set-credentials "janedoe-example-com" --token=$TOKEN
# with kubectl config get-clusters you can get clustername
kubectl config set-context "janedoe-example-com-context" --cluster="clustername" --user="janedoe-example-com" --namespace=default
kubectl config use-context janedoe-example-com-context
kubectl get pod
```
