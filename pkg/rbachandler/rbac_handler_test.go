// Copyright © 2019 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rbachandler

import (
	"os"
	"path"
	"testing"
	"time"

	"github.com/banzaicloud/jwt-to-rbac/internal/log"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/goph/logur"
	"github.com/stretchr/testify/assert"
	apicorev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

func createFakeConfig(groupName string) *Config {
	kubeconfig := path.Join(os.Getenv("HOME"), ".kube/config")
	customRule := CustomRule{
		Verbs:     []string{"get", "list"},
		Resources: []string{"deployments", "replicasets", "pods"},
		APIGroups: []string{"", "extensions", "apps"},
	}
	customGroup := CustomGroup{
		GroupName:   groupName,
		CustomRules: []CustomRule{customRule},
	}
	config := &Config{
		CustomGroups: []CustomGroup{customGroup},
		KubeConfig:   kubeconfig,
	}
	return config
}

func createFakeConfigNamespaces(groupName string) *Config {
	kubeconfig := path.Join(os.Getenv("HOME"), ".kube/config")
	customRule := CustomRule{
		Verbs:     []string{"get", "list"},
		Resources: []string{"deployments", "replicasets", "pods"},
		APIGroups: []string{"", "extensions", "apps"},
	}
	customGroup := CustomGroup{
		GroupName:   groupName,
		CustomRules: []CustomRule{customRule},
		NameSpaces:  []string{"helloworld"},
	}
	config := &Config{
		CustomGroups: []CustomGroup{customGroup},
		KubeConfig:   kubeconfig,
	}
	return config
}

func createLogger() logur.Logger {
	logConfig := log.Config{Format: "json", Level: "4", NoColor: true}
	logger := log.NewLogger(logConfig)
	return log.WithFields(logger, map[string]interface{}{"package": "rbachandler"})
}

func TestGenerateRules(t *testing.T) {
	assert := assert.New(t)
	rules := generateRules("developers", createFakeConfig("developers"))
	assert.ElementsMatch(rules[0].apiGroups, []string{"", "extensions", "apps"})
	assert.ElementsMatch(rules[0].resources, []string{"deployments", "replicasets", "pods"})
	assert.ElementsMatch(rules[0].verbs, []string{"get", "list"})

	rules = generateRules("developers", createFakeConfig("fakegroup"))
	assert.Equal(len(rules), 0)
}

func TestGenerateRbacResources(t *testing.T) {
	logger := createLogger()
	assert := assert.New(t)
	groups := []string{"admins", "developers"}
	federatedClaims := tokenhandler.FederatedClaims{
		ConnectorID: "ldap",
		UserID:      "cn=jane,ou=People,dc=example,dc=org",
	}
	user := &tokenhandler.User{
		Email:           "janedoe@example.com",
		Groups:          groups,
		FederatedClaims: federatedClaims,
	}
	testRbacResources, err := generateRbacResources(user, createFakeConfig("developers"), []string{"default"}, logger)
	assert.NoError(err)
	roleSuccess := assert.Equal(len(testRbacResources.clusterRoles), 1)
	assert.Equal(len(testRbacResources.clusterRoleBindings), 2)
	assert.Equal(testRbacResources.serviceAccount.Name, "janedoe-example-com")
	if roleSuccess {
		assert.Equal(testRbacResources.clusterRoles[0].name, "developers-from-jwt")
	}
	var bindNames, roleNames []string
	for _, crBind := range testRbacResources.clusterRoleBindings {
		bindNames = append(bindNames, crBind.name)
		roleNames = append(roleNames, crBind.roleName)
	}
	assert.ElementsMatch(bindNames, []string{"janedoe-example-com-admin-binding", "janedoe-example-com-developers-from-jwt-binding"})
	assert.ElementsMatch(roleNames, []string{"admin", "developers-from-jwt"})

	testRbacResources, err = generateRbacResources(user, createFakeConfig("fakegroup"), []string{"default"}, logger)
	assert.NoError(err)
	assert.Equal(len(testRbacResources.clusterRoles), 0)
	assert.Equal(len(testRbacResources.clusterRoleBindings), 1)
	assert.Equal(testRbacResources.serviceAccount.Name, "janedoe-example-com")
	bindNames = nil
	roleNames = nil
	for _, crBind := range testRbacResources.clusterRoleBindings {
		bindNames = append(bindNames, crBind.name)
		roleNames = append(roleNames, crBind.roleName)
	}
	assert.ElementsMatch(bindNames, []string{"janedoe-example-com-admin-binding"})
	assert.ElementsMatch(roleNames, []string{"admin"})
}

func TestGenerateRbacResourcesWithNameSpaces(t *testing.T) {
	logger := createLogger()
	assert := assert.New(t)
	groups := []string{"admins", "developers"}
	federatedClaims := tokenhandler.FederatedClaims{
		ConnectorID: "ldap",
		UserID:      "cn=jane,ou=People,dc=example,dc=org",
	}
	user := &tokenhandler.User{
		Email:           "janedoe@example.com",
		Groups:          groups,
		FederatedClaims: federatedClaims,
	}
	testRbacResources, err := generateRbacResources(user, createFakeConfigNamespaces("developers"), []string{"default"}, logger)
	assert.NoError(err)
	roleSuccess := assert.Equal(len(testRbacResources.clusterRoles), 1)
	assert.Equal(len(testRbacResources.roleBindings), 1)
	assert.Equal(len(testRbacResources.clusterRoleBindings), 1)
	assert.Equal(testRbacResources.serviceAccount.Name, "janedoe-example-com")
	if roleSuccess {
		assert.Equal(testRbacResources.clusterRoles[0].name, "developers-from-jwt")
	}
	var bindNames, roleNames, saNamespaces []string
	for _, crBind := range testRbacResources.clusterRoleBindings {
		bindNames = append(bindNames, crBind.name)
		roleNames = append(roleNames, crBind.roleName)
	}
	assert.ElementsMatch(bindNames, []string{"janedoe-example-com-admin-binding"})
	assert.ElementsMatch(roleNames, []string{"admin"})
	bindNames = nil
	roleNames = nil
	for _, crBind := range testRbacResources.roleBindings {
		bindNames = append(bindNames, crBind.name)
		roleNames = append(roleNames, crBind.roleName)
		saNamespaces = append(saNamespaces, crBind.saNameSpace...)
	}
	assert.ElementsMatch(bindNames, []string{"janedoe-example-com-developers-from-jwt-binding"})
	assert.ElementsMatch(roleNames, []string{"developers-from-jwt"})
	assert.ElementsMatch(saNamespaces, []string{"default"})

	testRbacResources, err = generateRbacResources(user, createFakeConfig("fakegroup"), []string{"default"}, logger)
	assert.NoError(err)
	assert.Equal(len(testRbacResources.clusterRoles), 0)
	assert.Equal(len(testRbacResources.clusterRoleBindings), 1)
	assert.Equal(testRbacResources.serviceAccount.Name, "janedoe-example-com")
	bindNames = nil
	roleNames = nil
	for _, crBind := range testRbacResources.clusterRoleBindings {
		bindNames = append(bindNames, crBind.name)
		roleNames = append(roleNames, crBind.roleName)
	}
	assert.ElementsMatch(bindNames, []string{"janedoe-example-com-admin-binding"})
	assert.ElementsMatch(roleNames, []string{"admin"})
	bindNames = nil
	roleNames = nil
	for _, crBind := range testRbacResources.roleBindings {
		bindNames = append(bindNames, crBind.name)
		roleNames = append(roleNames, crBind.roleName)
	}
	assert.ElementsMatch(bindNames, nil)
	assert.ElementsMatch(roleNames, nil)

}

func TestGenerateRbacResourcesWithEmailWithSpecialCharacters(t *testing.T) {
	logger := createLogger()
	assert := assert.New(t)
	groups := []string{"admins", "developers"}
	federatedClaims := tokenhandler.FederatedClaims{
		ConnectorID: "ldap",
		UserID:      "cn=jane,ou=People,dc=example,dc=org",
	}
	user := &tokenhandler.User{
		Email:           "jane.doe_foo@example.com",
		Groups:          groups,
		FederatedClaims: federatedClaims,
	}
	testRbacResources, err := generateRbacResources(user, createFakeConfig("developers"), []string{"default"}, logger)
	assert.NoError(err)
	roleSuccess := assert.Equal(len(testRbacResources.clusterRoles), 1)
	assert.Equal(len(testRbacResources.clusterRoleBindings), 2)
	assert.Equal(testRbacResources.serviceAccount.Name, "jane-doe-foo-example-com")
	if roleSuccess {
		assert.Equal(testRbacResources.clusterRoles[0].name, "developers-from-jwt")
	}
	var bindNames, roleNames []string
	for _, crBind := range testRbacResources.clusterRoleBindings {
		bindNames = append(bindNames, crBind.name)
		roleNames = append(roleNames, crBind.roleName)
	}
	assert.ElementsMatch(bindNames, []string{"jane-doe-foo-example-com-admin-binding", "jane-doe-foo-example-com-developers-from-jwt-binding"})
	assert.ElementsMatch(roleNames, []string{"admin", "developers-from-jwt"})

	testRbacResources, err = generateRbacResources(user, createFakeConfig("fakegroup"), []string{"default"}, logger)
	assert.NoError(err)
	assert.Equal(len(testRbacResources.clusterRoles), 0)
	assert.Equal(len(testRbacResources.clusterRoleBindings), 1)
	assert.Equal(testRbacResources.serviceAccount.Name, "jane-doe-foo-example-com")
	bindNames = nil
	roleNames = nil
	for _, crBind := range testRbacResources.clusterRoleBindings {
		bindNames = append(bindNames, crBind.name)
		roleNames = append(roleNames, crBind.roleName)
	}
	assert.ElementsMatch(bindNames, []string{"jane-doe-foo-example-com-admin-binding"})
	assert.ElementsMatch(roleNames, []string{"admin"})
}

func TestServiceAccountName(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		connectorID string
		email       string
		userID      string
		want        string
		wantErr     bool
	}{
		{connectorID: "ldap", email: "jane.doe_foo@example.com", want: "jane-doe-foo-example-com"},
		{connectorID: "local", email: "janedoe@example.com", want: "janedoe-example-com"},
		{connectorID: "github", email: "janedoe@example.com", userID: "13311234", want: "13311234"},
		{connectorID: "saml", email: "janedoe@example.com", wantErr: true},
	}
	for _, tt := range tests {
		user := &tokenhandler.User{
			Email:           tt.email,
			FederatedClaims: tokenhandler.FederatedClaims{ConnectorID: tt.connectorID, UserID: tt.userID},
		}
		saName, err := ServiceAccountName(user)
		if tt.wantErr {
			assert.Error(err)
			continue
		}
		assert.NoError(err)
		assert.Equal(tt.want, saName)
	}
}

func TestGenerateClusterRole(t *testing.T) {
	assert := assert.New(t)
	cRole, err := generateClusterRole("developers", createFakeConfig("developers"))
	assert.NoError(err)
	assert.Equal(cRole.name, "developers-from-jwt")
	_, err = generateClusterRole("developers", createFakeConfig("fakegroup"))
	assert.EqualError(err, "cannot find specified group in jwt-to-rbac config")
}

func skipWithoutCluster(t *testing.T, config *Config) {
	t.Helper()
	rbacHandler, err := NewRBACHandler(config.KubeConfig, createLogger())
	if err != nil {
		t.Skipf("skipping: no usable kubeconfig: %v", err)
	}
	if _, err := rbacHandler.listClusterroles(); err != nil {
		t.Skipf("skipping: no reachable Kubernetes cluster: %v", err)
	}
}

func TestListClusterroleBindings(t *testing.T) {
	assert := assert.New(t)
	config := createFakeConfig("developers")
	skipWithoutCluster(t, config)
	_, err := ListRBACResources(config, createLogger())
	assert.NoError(err)
}

func TestGetAndCheckSA(t *testing.T) {
	assert := assert.New(t)
	config := createFakeConfig("developers")
	skipWithoutCluster(t, config)
	rbacHandler, err := NewRBACHandler(config.KubeConfig, createLogger())
	assert.NoError(err)
	_, err = rbacHandler.getAndCheckSA("default")
	assert.EqualError(err, "getting not jwt-to-rbac generated ServiceAccount is forbidden: label mismatch in serviceaccount")
}

func tokenSecret(name string, token string, created time.Time) *apicorev1.Secret {
	data := map[string][]byte{
		apicorev1.ServiceAccountRootCAKey:    []byte("example-ca"),
		apicorev1.ServiceAccountNamespaceKey: []byte("default"),
	}
	if token != "" {
		data[apicorev1.ServiceAccountTokenKey] = []byte(token)
	}
	return &apicorev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: metav1.NewTime(created)},
		Data:       data,
	}
}

func TestLatestTokenSecret(t *testing.T) {
	assert := assert.New(t)
	now := time.Now()
	secret, err := latestTokenSecret([]*apicorev1.Secret{
		tokenSecret("old", "old-token", now.Add(-2*time.Hour)),
		tokenSecret("pending", "", now),
		tokenSecret("new", "new-token", now.Add(-time.Hour)),
	})
	assert.NoError(err)
	assert.Equal("new", secret.Name)

	_, err = latestTokenSecret([]*apicorev1.Secret{tokenSecret("pending", "", now)})
	assert.Error(err)
	_, err = latestTokenSecret(nil)
	assert.Error(err)
}

func TestGenerateKubeconfig(t *testing.T) {
	assert := assert.New(t)
	secret := tokenSecret("janedoe-example-com-token-abcde", "example-token", time.Now())
	b, err := generateKubeconfig("janedoe-example-com", "example-cluster", "https://example.com:6443", secret)
	assert.NoError(err)

	kubeconfig, err := clientcmd.Load(b)
	assert.NoError(err)
	assert.Equal("janedoe-example-com@example-cluster", kubeconfig.CurrentContext)
	context := kubeconfig.Contexts[kubeconfig.CurrentContext]
	if assert.NotNil(context) {
		assert.Equal("example-cluster", context.Cluster)
		assert.Equal("janedoe-example-com", context.AuthInfo)
		assert.Equal("default", context.Namespace)
	}
	cluster := kubeconfig.Clusters["example-cluster"]
	if assert.NotNil(cluster) {
		assert.Equal("https://example.com:6443", cluster.Server)
		assert.Equal([]byte("example-ca"), cluster.CertificateAuthorityData)
	}
	authInfo := kubeconfig.AuthInfos["janedoe-example-com"]
	if assert.NotNil(authInfo) {
		assert.Equal("example-token", authInfo.Token)
	}
}
