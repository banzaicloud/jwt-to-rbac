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
	"flag"
	"strings"

	"github.com/banzaicloud/jwt-to-rbac/internal/errorhandler"
	"github.com/banzaicloud/jwt-to-rbac/internal/log"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"

	"github.com/goph/emperror"
	"github.com/goph/logur"
	apicorev1 "k8s.io/api/core/v1"
	apirbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	clientrbacv1 "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var logger logur.Logger
var errorHandler emperror.Handler

type rules struct {
	verbs     []string
	resources []string
	apiGroups []string
}

// clusterRole implements create ClusterRole
type clusterRole struct {
	name  string
	rules []rules
}

// clusterRoleBinding implements create ClusterRoleBinding
type clusterRoleBinding struct {
	name      string
	saName    string
	roleName  string
	nameSpace []string
}

// serviceAccount implements create ServiceAccount
type serviceAccount struct {
	name string
}

type rbacResources struct {
	clusterRoles        []clusterRole
	clusterRoleBindings []clusterRoleBinding
	serviceAccount      serviceAccount
}

var coreConf *clientcorev1.CoreV1Client
var rbacConf *clientrbacv1.RbacV1Client

func init() {
	var kubeconfig string
	// flag.StringVar(&kubeconfig, "", "", "path to Kubernetes config file")
	flag.StringVar(&kubeconfig, "kubeconfig", "/Users/poke/.kube/config", "path to Kubernetes config file")
	flag.Parse()

	logConfig := log.Config{Format: "json", Level: "4", NoColor: true}
	logger = log.NewLogger(logConfig)
	logger = log.WithFields(logger, map[string]interface{}{"package": "rbachandler"})

	errorHandler = errorhandler.New(logger)
	defer emperror.HandleRecover(errorHandler)

	clusterConfig, err := getK8sConfig(kubeconfig)
	if err != nil {
		errorHandler.Handle(err)
	}
	coreConf, err = clientcorev1.NewForConfig(clusterConfig)
	if err != nil {
		errorHandler.Handle(err)
	}
	rbacConf, err = clientrbacv1.NewForConfig(clusterConfig)
	if err != nil {
		errorHandler.Handle(err)
	}
}

func getK8sConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		logger.Debug("using in-cluster configuration", nil)
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, emperror.Wrap(err, "failed to get incluster config")
		}
		return config, nil
	}
	logger.Debug("using configuration from", map[string]interface{}{"kubeconfig": kubeconfig})
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, emperror.Wrap(err, "failed to get kubernetes config")
	}
	return config, nil
}

// ListClusterroleBindings clusterrolebindings
func ListClusterroleBindings() []string {
	bindings := rbacConf.ClusterRoleBindings()
	binds, _ := bindings.List(metav1.ListOptions{})
	var rbacList []string
	for _, b := range binds.Items {
		rbacList = append(rbacList, b.GetName())
	}
	ListServiceAccount()
	return rbacList
}

// ListServiceAccount list serviceaccount
func ListServiceAccount() []string {
	serviceAccountList, _ := coreConf.ServiceAccounts("").List(metav1.ListOptions{})
	var serviceAccList []string
	for _, serviceAcc := range serviceAccountList.Items {
		serviceAccList = append(serviceAccList, serviceAcc.GetName())
	}
	return serviceAccList
}

func listNamespaces() []string {
	namespaceList, _ := coreConf.Namespaces().List(metav1.ListOptions{})
	var nsList []string
	for _, namespace := range namespaceList.Items {
		nsList = append(nsList, namespace.GetName())
	}
	return nsList
}

func (sa *serviceAccount) create() error {
	saObj := &apicorev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sa.name,
			Namespace: "default",
		},
	}
	_, err := coreConf.ServiceAccounts("default").Create(saObj)
	if err != nil {
		return emperror.WrapWith(err, "create serviceaccount failed", "saName", sa)
	}
	return nil
}

func (rb *clusterRoleBinding) create() error {
	var subjects []apirbacv1.Subject
	for _, ns := range rb.nameSpace {
		subject := apirbacv1.Subject{
			Kind:      "ServiceAccount",
			APIGroup:  "",
			Name:      rb.saName,
			Namespace: ns,
		}
		subjects = append(subjects, subject)
	}
	bindObj := &apirbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: rb.name,
		},
		Subjects: subjects,
		RoleRef: apirbacv1.RoleRef{
			Kind:     "ClusterRole",
			APIGroup: "rbac.authorization.k8s.io",
			Name:     rb.roleName,
		},
	}
	_, err := rbacConf.ClusterRoleBindings().Create(bindObj)
	if err != nil {
		return emperror.WrapWith(err, "create clusterrolebinding failed", "ClusterRoleBinding", rb.name)
	}
	return nil
}

func (r *clusterRole) create() error {
	var rules []apirbacv1.PolicyRule
	for _, rule := range r.rules {
		rule := apirbacv1.PolicyRule{
			Verbs:     rule.verbs,
			Resources: rule.resources,
			APIGroups: rule.apiGroups,
		}
		rules = append(rules, rule)
	}
	roleObj := &apirbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: r.name,
		},
		Rules: rules,
	}
	_, err := rbacConf.ClusterRoles().Create(roleObj)
	if err != nil {
		return emperror.WrapWith(err, "create clusterrole failed", "ClusterRole", r.name)
	}
	return nil
}

func generateRbacResources(user *tokenhandler.User) *rbacResources {
	var saName string
	if user.FederatedClaimas.ConnectorID == "github" {
		saName = user.FederatedClaimas.UserID
	} else if user.FederatedClaimas.ConnectorID == "ldap" {
		r := strings.NewReplacer("@", "-", ".", "-")
		saName = r.Replace(user.Email)
	}

	rule := rules{
		verbs: []string{
			"get",
			"list",
		},
		resources: []string{
			"deployments",
			"replicasets",
			"pods",
		},
		apiGroups: []string{
			"",
			"extensions",
			"apps",
		},
	}

	var clusterRoles []clusterRole
	var clusterRoleBindings []clusterRoleBinding
	for _, group := range user.Groups {
		cRole := clusterRole{
			name:  group + "-from-jwt",
			rules: []rules{rule},
		}
		clusterRoles = append(clusterRoles, cRole)
		cRoleBinding := clusterRoleBinding{
			name:      saName + "-" + group + "-binding",
			saName:    saName,
			roleName:  group + "-from-jwt",
			nameSpace: listNamespaces(),
		}
		clusterRoleBindings = append(clusterRoleBindings, cRoleBinding)
	}

	rbacResources := &rbacResources{
		clusterRoles:        clusterRoles,
		clusterRoleBindings: clusterRoleBindings,
		serviceAccount: serviceAccount{
			name: saName,
		},
	}
	return rbacResources
}

// CreateRBAC create RBAC resources
func CreateRBAC(user *tokenhandler.User) {
	rbacResources := generateRbacResources(user)
	err := rbacResources.serviceAccount.create()
	if err != nil {
		errorHandler.Handle(err)
	}

	for _, clusterRole := range rbacResources.clusterRoles {
		err = clusterRole.create()
		if err != nil {
			errorHandler.Handle(err)
		}
	}
	for _, clusterRoleBinding := range rbacResources.clusterRoleBindings {
		err := clusterRoleBinding.create()
		if err != nil {
			errorHandler.Handle(err)
		}
	}
}
