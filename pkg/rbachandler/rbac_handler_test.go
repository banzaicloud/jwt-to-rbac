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
	"testing"

	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/stretchr/testify/assert"
)

func TestGenerateRules(t *testing.T) {
	assert := assert.New(t)
	rules := generateRules()
	for _, rule := range rules {
		assert.NotEqual(len(rule.apiGroups), 0)
		assert.NotEqual(len(rule.resources), 0)
		assert.NotEqual(len(rule.verbs), 0)
	}
}

func TestGenerateRbacResources(t *testing.T) {
	assert := assert.New(t)
	groups := []string{"admin", "developers"}
	federatedClaims := tokenhandler.FederatedClaims{
		ConnectorID: "ldap",
		UserID:      "cn=jane,ou=People,dc=example,dc=org",
	}
	user := &tokenhandler.User{
		Email:            "janedoe@example.com",
		Groups:           groups,
		FederatedClaimas: federatedClaims,
	}

	testRbacResources := generateRbacResources(user)
	assert.Equal(len(testRbacResources.clusterRoles), 1)
	assert.Equal(len(testRbacResources.clusterRoleBindings), 2)
	assert.Equal(testRbacResources.serviceAccount.name, "janedoe-example-com")
	assert.Equal(testRbacResources.clusterRoles[0].name, "developers-from-jwt")
	var bindNames, roleNames []string
	for _, crBind := range testRbacResources.clusterRoleBindings {
		bindNames = append(bindNames, crBind.name)
		roleNames = append(roleNames, crBind.roleName)
	}
	assert.ElementsMatch(bindNames, []string{"janedoe-example-com-admin-binding", "janedoe-example-com-developers-from-jwt-binding"})
	assert.ElementsMatch(roleNames, []string{"admin", "developers-from-jwt"})
}
