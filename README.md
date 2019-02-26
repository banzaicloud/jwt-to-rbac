[![CircleCI](https://circleci.com/gh/banzaicloud/jwt-to-rbac/tree/master.svg?style=shield)](https://circleci.com/gh/banzaicloud/jwt-to-rbac/tree/master)

## JWT-to-RBAC

JWT-to-RBAC lets you automatically generate RBAC resources based on JWT token. 

### Context 

For authentication we use [Dex](https://github.com/dexidp/dex) with the LDAP connector. The user in LDAP has group memberships and Dex issues a JWT token containing these memberships. The JWT-to-RBAC project can create `ServiceAccount`, `ClusterRoles` and `ClusterroleBindings` based on JWT tokens. When we create a new `ServiceAccount` K8s automatically generates a `service account token`.

For more information and context please read the [Provider agnostic authentication and authorization in Kubernetes](https://banzaicloud.com/blog/k8s-rbac/) post.

JWT-to-RBAC is a core part of [Banzai Cloud Pipeline](https://banzaicloud.com/), a Cloud Native application and devops platform that natively supports multi- and hybrid-cloud deployments with multiple authentication backends. Check out the developer beta:
<p align="center">
  <a href="https://beta.banzaicloud.io">
  <img src="https://camo.githubusercontent.com/a487fb3128bcd1ef9fc1bf97ead8d6d6a442049a/68747470733a2f2f62616e7a6169636c6f75642e636f6d2f696d672f7472795f706970656c696e655f627574746f6e2e737667">
  </a>
</p>

### Requirements:

There are some pre-requirements to kick this of for your own testing.

* Configured Dex server which issues JWT tokens. If you want to issue tokens with Dex you have to configure it with LDAP connector. You can use the Banzai Cloud [Dex chart](https://github.com/banzaicloud/banzai-charts/tree/master/dex). 
* Configured LDAP server - you can use the [openldap](https://github.com/osixia/docker-openldap) Docker image
* Authentication application which uses Dex as an OpenID connector (in our case is [Pipeline](https://github.com/banzaicloud/pipeline).

> Dex acts as a shim between a client app and the upstream identity provider. The client only needs to understand OpenID Connect to query Dex.

The whole process is broken down to two main parts:

* Dex auth flow
* jwt-to-rbac ServiceAccount creation flow

**Dex authentication flow:**

1. User visits Authentication App.
2. Authentication App redirects user to Dex with an OAuth2 request.
3. Dex determines user's identity.
4. Dex redirects user to Authentication App with a code.
5. Authentication App exchanges code with Dex for an ID token.

**jwt-to-rbac Flow:**

1. Authentication App has ID token (JWT)
2. POST ID token to jwt-to-rbac App
3. jwt-to-rbac validates ID token with Dex
4. jwt-to-rbac extracts username, groups and so on from the token
5. jwt-to-rbac calls API server to crate `ServiceAccount`, `ClusterRoles` and `ClusterRoleBindings`
6. jwt-to-rbac get service account token and sends it to Authentication App
7. Authentication App sends back the service account token to User
8. User authenticate on K8s using `service account token`

**The ID token issued by Dex has a following content:**
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

After jwt-to-rbac extracts the information from the token, creates `ServiceAccount` and `ClusterRoleBinding` using one of the default K8s `ClusterRole` as `roleRef` or generate one defined in configuration if it does't exist.

### Default K8s ClusterRoles used by `jwt-to-rbac`

The [JWT-to-RBAC](https://github.com/banzaicloud/jwt-to-rbac) dos not create a new `ClusterRole` in every case; for example if a user is a member of admin group, it doesn't create this `ClusterRole` because K8s has already one by default.

Default ClusterRole | Description 
--------------------|------------
cluster-admin       | Allows super-user access to perform any action on any resource.
admin               | Allows admin access, intended to be granted within a namespace using a RoleBinding.
edit                | Allows read/write access to most objects in a namespace.
view                | Allows read-only access to see most objects in a namespace.

### jwt-to-rbac crate custom `ClusterRole` defined in config

In most of the cases there are different LDAP groups, so custom groups can be configured with custom rules.

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

### define github custom roles in config

```toml
[[rbachandler.customGroups]]
groupName = "githubOrg-githubTeam"
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

### or specify github organization as default org

```toml
[rbachandler]
githubOrg = "github_organization"
[[rbachandler.customGroups]]
groupName = "githubTeam"
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

### Example configuration in yaml using default github org
**issued jwt:**
```json
{
  "iss": "http://dex/dex",
  "sub": "xxxxxxxxxxxxxxxxxxxxx",
  "aud": "example-app",
  "exp": 1551179050,
  "iat": 1551092650,
  "at_hash": "xxxxxxxxxxxxxxxxxxx",
  "email": "p.balogh.sa@gmail.com",
  "email_verified": true,
  "groups": [
    "pokeorg",
    "pokeorg:admin",
    "pokeorg:developer"
  ],
  "name": "Peter Balogh",
  "federated_claims": {
    "connector_id": "github",
    "user_id": "13311234"
  }
}
```
**example config:**
```yaml
app:
  addr: ":5555"

log:
  level: "4"
  format: "json"
  noColor: true

tokenhandler:
  dex:
    clientID: example-app
    issuerURL: "http://dex/dex"

rbachandler:
  githubOrg: "pokeorg"
  customGroups:
  - groupName: developer
    customRules:
    - verbs: [ "get", "list" ]
      resources: [ "deployments", "replicasets", "pods" ]
      apiGroups: [ "", "extensions", "apps" ]
  kubeConfig: "/Users/poke/.kube/config"
```

### Define custom CA cert or set insecure connection
```toml
[tokenhandler]
caCertPath = "/path/to/tls.crt"
insecure = false
```
**Setting insecure conection in command line:**
```shel
jwt-to-rbac --tokenhandler.insecure=true
```

So to conclude on the open source [JWT-to-RBAC](https://github.com/banzaicloud/jwt-to-rbac) project - follow these stpes if you would like to try it or check it out already in action by subscribing to our free developer beta at https://beta.banzaicloud.io/.

### 1. Deploy jwt-to-rbac to Kubernetes

After you cloning the [GitHub repository](https://github.com/banzaicloud/jwt-to-rbac) you can compile a code and make a `docker image` with one command.

```shell
make docker
```

If you are using docker-for-desktop or minikube, you'll be able to deploy it using locally with the newly built image.
```shell
kubectl create -f deploy/rbac.yaml
kubectl create -f deploy/configmap.yaml
kubectl create -f deploy/deployment.yaml
kubectl create -f deploy/service.yaml
# port-forward locally
kubectl port-forward svc/jwt-to-rbac 5555
```

Now you can communicate with the jwt-to-rbac app.

### 2. POST ID token issued by Dex to jwt-to-rbac API
```shell
curl --request POST \
  --url http://localhost:5555/rbac \
  --header 'Content-Type: application/json' \
  --data '{\n	"token": "example.jwt.token"\n}'

# response:
{
    "Email": "janedoe@example.com",
    "Groups": [
        "admins",
        "developers"
    ],
    "FederatedClaims": {
        "connector_id": "ldap",
        "user_id": "cn=jane,ou=People,dc=example,dc=org"
    }
}
```

The `ServiceAccount`, `ClusterRoles` (if ID token has some defined custom groups we discussed) and `ClusterRoleBindings` are created.

**Listing the created K8s resources:**
```shell
curl --request GET \
  --url http://localhost:5555/rbac \
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

### 3. GET the default K8s token of `ServiceAccount`
```shell
curl --request GET \
  --url http://localhost:5555/tokens/janedoe-example-com \
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

### 4. Generate a ServiceAccount token with TTL
```shell
curl --request POST \
  --url http://localhost:5555/tokens/janedoe-example-com \
  --header 'Content-Type: application/json'
  --data '{\n"duration": "12h30m"\n}'

# response:
[
    {
        "name": "janedoe-example-com-token-df3re",
        "data": {
            "ca.crt": "example-ca-cer-base64",
            "namespace": "ZGVmYXVsdA==",
            "token": "example-k8s-sa-token-with-ttl-base64"
        }
    }
]
```

Now you have a base64 encoded `service account token`.

### 5. Accessing with ServiceAccount token 

You can use `service account token` from command line:
```shell
kubectl --token $TOKEN_TEST --server $APISERVER get po
```

Or create `kubectl` context with it:
```shell
export TOKEN=$(echo "example-k8s-sa-token-base64" | base64 -D)
kubectl config set-credentials "janedoe-example-com" --token=$TOKEN
# with kubectl config get-clusters you can get cluster name
kubectl config set-context "janedoe-example-com-context" --cluster="clustername" --user="janedoe-example-com" --namespace=default
kubectl config use-context janedoe-example-com-context
kubectl get pod
```

> As a final note - since we use Dex, which is an identity service that uses OpenID Connect to drive authentication for other apps, any other supported connector can be used for authentication to Kubernetes.
