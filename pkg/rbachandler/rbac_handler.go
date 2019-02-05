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
	"errors"
	"fmt"
	"strings"

	"github.com/banzaicloud/jwt-to-rbac/internal/config"
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

const defautlLabelKey string = "generatedby"

var defaultLabel = labels{
	defautlLabelKey: "jwttorbac",
}

type rule struct {
	verbs     []string
	resources []string
	apiGroups []string
}

type labels map[string]string

// clusterRole implements create ClusterRole
type clusterRole struct {
	name   string
	rules  []rule
	labels labels
}

// clusterRoleBinding implements create ClusterRoleBinding
type clusterRoleBinding struct {
	name      string
	saName    string
	roleName  string
	nameSpace []string
	labels    labels
}

// serviceAccount implements create ServiceAccount
type serviceAccount struct {
	name      string
	labels    labels
	namespace string
}

type rbacResources struct {
	clusterRoles        []clusterRole
	clusterRoleBindings []clusterRoleBinding
	serviceAccount      serviceAccount
}

// RBACHandler struct
type RBACHandler struct {
	coreClientSet *clientcorev1.CoreV1Client
	rbacClientSet *clientrbacv1.RbacV1Client
}

func init() {
	logConfig := log.Config{Format: "json", Level: "4", NoColor: true}
	logger = log.NewLogger(logConfig)
	logger = log.WithFields(logger, map[string]interface{}{"package": "rbachandler"})
}

// NewRBACHandler create RBACHandler
func NewRBACHandler(kubeconfig string) (*RBACHandler, error) {
	coreClientSet, rbacClientSet, err := getK8sClientSets(kubeconfig)
	if err != nil {
		return nil, err
	}
	return &RBACHandler{coreClientSet, rbacClientSet}, nil
}

func getK8sClientSets(kubeconfig string) (*clientcorev1.CoreV1Client, *clientrbacv1.RbacV1Client, error) {
	logger.Info("Kubeconfig get info", map[string]interface{}{"KubeConfig": kubeconfig})
	var config *rest.Config
	var err error
	if kubeconfig == "" {
		logger.Debug("using in-cluster configuration", nil)
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, nil, emperror.Wrap(err, "failed to get incluster config")
		}
	} else {
		logger.Debug("using configuration from", map[string]interface{}{"kubeconfig": kubeconfig})
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, nil, emperror.WrapWith(err, "failed to get kubernetes config", "kubeconfig", kubeconfig)
		}
	}

	coreClientSet, err := clientcorev1.NewForConfig(config)
	if err != nil {
		return nil, nil, emperror.Wrap(err, "cannot create new core clientSet")
	}
	rbacClientSet, err := clientrbacv1.NewForConfig(config)
	if err != nil {
		return nil, nil, emperror.Wrap(err, "cannot create new rbac clientSet")
	}
	return coreClientSet, rbacClientSet, nil
}

// ListClusterroleBindings clusterrolebindings
func ListClusterroleBindings(config *config.Config) ([]string, error) {
	rbacHandler, err := NewRBACHandler(config.KubeConfig)
	if err != nil {
		return nil, err
	}
	rbacList, err := rbacHandler.listClusterroleBindings()
	if err != nil {
		return nil, err
	}
	return rbacList, nil
}

func (rh *RBACHandler) listClusterroleBindings() ([]string, error) {
	bindings := rh.rbacClientSet.ClusterRoleBindings()
	binds, err := bindings.List(metav1.ListOptions{})
	if err != nil {
		return nil, emperror.WrapWith(err, "unable to list bindings", "ListOptions", metav1.ListOptions{})
	}
	var rbacList []string
	for _, b := range binds.Items {
		rbacList = append(rbacList, b.GetName())
	}
	rh.listServiceAccount()
	return rbacList, nil
}

// ListServiceAccount list serviceaccount
func (rh *RBACHandler) listServiceAccount() ([]string, error) {
	labelSelect := fmt.Sprintf("%s=%s", defautlLabelKey, defaultLabel[defautlLabelKey])
	listOptions := metav1.ListOptions{
		LabelSelector: labelSelect,
	}
	serviceAccountList, err := rh.coreClientSet.ServiceAccounts("").List(listOptions)
	if err != nil {
		return nil, emperror.WrapWith(err, "cannot list ServiceAccounts", "label_selector", defaultLabel)
	}
	var serviceAccList []string
	for _, serviceAcc := range serviceAccountList.Items {
		serviceAccList = append(serviceAccList, serviceAcc.GetName())
	}
	return serviceAccList, nil
}

func (rh *RBACHandler) listNamespaces() ([]string, error) {
	namespaceList, err := rh.coreClientSet.Namespaces().List(metav1.ListOptions{})
	if err != nil {
		return nil, emperror.Wrap(err, "listing namespaces failed")
	}
	var nsList []string
	for _, namespace := range namespaceList.Items {
		nsList = append(nsList, namespace.GetName())
	}
	return nsList, nil
}

func (rh *RBACHandler) createServiceAccount(sa *serviceAccount) error {
	saObj := &apicorev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sa.name,
			Namespace: sa.namespace,
			Labels:    sa.labels,
		},
	}
	_, err := rh.coreClientSet.ServiceAccounts("default").Create(saObj)
	if err != nil {
		return emperror.WrapWith(err, "create serviceaccount failed", "saName", sa)
	}
	return nil
}

func (rh *RBACHandler) createClusterRoleBinding(crb *clusterRoleBinding) error {
	var subjects []apirbacv1.Subject
	for _, ns := range crb.nameSpace {
		subject := apirbacv1.Subject{
			Kind:      "ServiceAccount",
			APIGroup:  "",
			Name:      crb.saName,
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
			Name:   crb.name,
			Labels: crb.labels,
		},
		Subjects: subjects,
		RoleRef: apirbacv1.RoleRef{
			Kind:     "ClusterRole",
			APIGroup: "rbac.authorization.k8s.io",
			Name:     crb.roleName,
		},
	}
	_, err := rh.rbacClientSet.ClusterRoleBindings().Create(bindObj)
	if err != nil {
		return emperror.WrapWith(err, "create clusterrolebinding failed", "ClusterRoleBinding", crb.name)
	}
	return nil
}

func (rh *RBACHandler) createCluterRole(cr *clusterRole) error {
	var rules []apirbacv1.PolicyRule
	for _, rule := range cr.rules {
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
			Name:   cr.name,
			Labels: cr.labels,
		},
		Rules: rules,
	}
	_, err := rh.rbacClientSet.ClusterRoles().Create(roleObj)
	if err != nil {
		return emperror.WrapWith(err, "create clusterrole failed", "ClusterRole", cr.name)
	}
	return nil
}

func generateRules(groupName string, config *config.Config) []rule {
	var cRules []rule
	for _, cGroup := range config.CustomGroups {
		if cGroup.GroupName == groupName {
			for _, cRule := range cGroup.CustomRules {
				rule := rule{
					verbs:     cRule.Verbs,
					resources: cRule.Resources,
					apiGroups: cRule.APIGroups,
				}
				cRules = append(cRules, rule)
			}
			break
		}
	}
	return cRules
}

func generateClusterRole(group string, config *config.Config) (clusterRole, error) {
	rules := generateRules(group, config)
	if len(rules) < 1 {
		return clusterRole{}, emperror.With(errors.New("cannot find specified group in jwt-to-rbac config"), "groupName", group)
	}
	cRole := clusterRole{
		name:   group + "-from-jwt",
		rules:  rules,
		labels: defaultLabel,
	}
	return cRole, nil
}

func generateRbacResources(user *tokenhandler.User, config *config.Config, nameSpaces []string) (*rbacResources, error) {
	var saName string
	if user.FederatedClaimas.ConnectorID == "github" {
		saName = user.FederatedClaimas.UserID
	} else if user.FederatedClaimas.ConnectorID == "ldap" || user.FederatedClaimas.ConnectorID == "local" {
		r := strings.NewReplacer("@", "-", ".", "-")
		saName = r.Replace(user.Email)
	}

	var clusterRoles []clusterRole
	var clusterRoleBindings []clusterRoleBinding
	for _, group := range user.Groups {
		var roleName string
		switch group {
		case "cluster-admin", "admin", "edit", "view":
			roleName = group
		case "admins":
			roleName = "admin"
		default:
			cRole, err := generateClusterRole(group, config)
			if err != nil {
				logger.Info(err.Error(), map[string]interface{}{"group": group})
				continue
			}
			clusterRoles = append(clusterRoles, cRole)
			roleName = group + "-from-jwt"
		}
		cRoleBinding := clusterRoleBinding{
			name:      saName + "-" + roleName + "-binding",
			saName:    saName,
			roleName:  roleName,
			nameSpace: nameSpaces,
			labels:    defaultLabel,
		}
		clusterRoleBindings = append(clusterRoleBindings, cRoleBinding)
	}

	rbacResources := &rbacResources{
		clusterRoles:        clusterRoles,
		clusterRoleBindings: clusterRoleBindings,
		serviceAccount: serviceAccount{
			name:   saName,
			labels: defaultLabel,
		},
	}
	return rbacResources, nil
}

// CreateRBAC create RBAC resources
func CreateRBAC(user *tokenhandler.User, config *config.Config) error {
	rbacHandler, err := NewRBACHandler(config.KubeConfig)
	if err != nil {

	}
	nameSpaces, err := rbacHandler.listNamespaces()
	if err != nil {
		return err
	}
	rbacResources, err := generateRbacResources(user, config, nameSpaces)
	if err != nil {
		logger.Error(err.Error(), nil)
		return err
	}
	err = rbacHandler.createServiceAccount(&rbacResources.serviceAccount)
	if err != nil {
		logger.Error(err.Error(), nil)
		return err
	}
	if len(rbacResources.clusterRoles) > 0 {
		for _, clusterRole := range rbacResources.clusterRoles {
			err = rbacHandler.createCluterRole(&clusterRole)
			if err != nil {
				logger.Error(err.Error(), nil)
				return err
			}
		}
	}
	for _, clusterRoleBinding := range rbacResources.clusterRoleBindings {
		err = rbacHandler.createClusterRoleBinding(&clusterRoleBinding)
		if err != nil {
			logger.Error(err.Error(), nil)
			return err
		}
	}
	return nil
}
