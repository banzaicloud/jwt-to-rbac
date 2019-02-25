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
	"math/rand"
	"strings"
	"time"

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

// RBACHandler implements getting, creating and deleting resources
type RBACHandler struct {
	coreClientSet *clientcorev1.CoreV1Client
	rbacClientSet *clientrbacv1.RbacV1Client
}

type RBACList struct {
	SAList        []string `json:"sa_list,omitempty"`
	CRoleList     []string `json:"crole_list,omitempty"`
	CRoleBindList []string `json:"crolebind_list,omitempty"`
}

type SACredential struct {
	Name string            `json:"name"`
	Data map[string][]byte `json:"data"`
}

// NewRBACHandler create RBACHandler
func NewRBACHandler(kubeconfig string, logger logur.Logger) (*RBACHandler, error) {
	coreClientSet, rbacClientSet, err := getK8sClientSets(kubeconfig, logger)
	if err != nil {
		return nil, err
	}
	return &RBACHandler{coreClientSet, rbacClientSet}, nil
}

func getK8sClientSets(kubeconfig string, logger logur.Logger) (*clientcorev1.CoreV1Client, *clientrbacv1.RbacV1Client, error) {
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

// ListRBACResources clusterrolebindings
func ListRBACResources(config *Config, logger logur.Logger) (*RBACList, error) {
	logger = log.WithFields(logger, map[string]interface{}{"package": "rbachandler"})
	rbacHandler, err := NewRBACHandler(config.KubeConfig, logger)
	if err != nil {
		return &RBACList{}, err
	}
	cRoleBindList, err := rbacHandler.listClusterroleBindings()
	if err != nil {
		return &RBACList{}, err
	}
	cRoleList, err := rbacHandler.listClusterroles()
	if err != nil {
		return &RBACList{}, err
	}
	saList, err := rbacHandler.listServiceAccount()
	if err != nil {
		return &RBACList{}, err
	}
	rbacList := &RBACList{
		CRoleBindList: cRoleBindList,
		CRoleList:     cRoleList,
		SAList:        saList,
	}
	return rbacList, nil
}

func (rh *RBACHandler) listClusterroleBindings() ([]string, error) {
	bindings := rh.rbacClientSet.ClusterRoleBindings()
	labelSelect := fmt.Sprintf("%s=%s", defautlLabelKey, defaultLabel[defautlLabelKey])
	listOptions := metav1.ListOptions{
		LabelSelector: labelSelect,
	}
	binds, err := bindings.List(listOptions)
	if err != nil {
		return nil, emperror.WrapWith(err, "unable to list bindings", "ListOptions", metav1.ListOptions{})
	}
	var cRoleBindList []string
	for _, b := range binds.Items {
		cRoleBindList = append(cRoleBindList, b.GetName())
	}
	return cRoleBindList, nil
}

func (rh *RBACHandler) listClusterroles() ([]string, error) {
	clusterRoles := rh.rbacClientSet.ClusterRoles()
	labelSelect := fmt.Sprintf("%s=%s", defautlLabelKey, defaultLabel[defautlLabelKey])
	listOptions := metav1.ListOptions{
		LabelSelector: labelSelect,
	}
	cRoles, err := clusterRoles.List(listOptions)
	if err != nil {
		return nil, emperror.WrapWith(err, "unable to list clusterroles", "ListOptions", metav1.ListOptions{})
	}
	var cRoleList []string
	for _, b := range cRoles.Items {
		cRoleList = append(cRoleList, b.GetName())
	}
	return cRoleList, nil
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

func (rh *RBACHandler) createServiceAccount(sa *serviceAccount) error {
	if _, err := rh.getAndCheckSA(sa.name); err == nil {
		return nil
	}
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
	if err := rh.getAndCheckCRoleBinding(crb.name); err == nil {
		return nil
	}
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
	ownerReferences, err := rh.getSAReference(crb.saName)
	if err != nil {
		return err
	}
	bindObj.SetOwnerReferences(ownerReferences)
	_, err = rh.rbacClientSet.ClusterRoleBindings().Create(bindObj)
	if err != nil {
		return emperror.WrapWith(err, "create clusterrolebinding failed", "ClusterRoleBinding", crb.name)
	}
	return nil
}

func (rh *RBACHandler) createClusterRole(cr *clusterRole) error {
	if err := rh.getAndCheckCRole(cr.name); err == nil {
		return nil
	}
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

func generateRules(groupName string, config *Config) []rule {
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

func generateClusterRole(group string, config *Config) (clusterRole, error) {
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

func githubRoleParser(groups []string, org string) []string {
	var groupList []string
	for _, group := range groups {
		if strings.Contains(group, ":") {
			orgGroup := strings.Split(group, ":")
			if orgGroup[0] == org {
				groupList = append(groupList, orgGroup[1])
				continue
			}
			groupList = append(groupList, fmt.Sprintf("%s-%s", orgGroup[0], orgGroup[1]))
			continue
		}
	}
	return groupList
}

func generateRbacResources(user *tokenhandler.User, config *Config, nameSpaces []string, logger logur.Logger) (*rbacResources, error) {
	var saName string
	var groupList []string
	switch user.FederatedClaims.ConnectorID {
	case "github":
		saName = user.FederatedClaims.UserID
		groupList = githubRoleParser(user.Groups, config.GithubOrg)
	case "ldap", "local":
		r := strings.NewReplacer("@", "-", ".", "-")
		saName = r.Replace(user.Email)
		groupList = user.Groups
	default:
		return nil, emperror.With(errors.New("connector is not implemented yet"), "ConnectorID", user.FederatedClaims.ConnectorID)
	}

	var clusterRoles []clusterRole
	var clusterRoleBindings []clusterRoleBinding
	for _, group := range groupList {
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
func CreateRBAC(user *tokenhandler.User, config *Config, logger logur.Logger) error {
	logger = log.WithFields(logger, map[string]interface{}{"package": "rbachandler"})

	rbacHandler, err := NewRBACHandler(config.KubeConfig, logger)
	if err != nil {
		return err
	}
	rbacResources, err := generateRbacResources(user, config, []string{"default"}, logger)
	if err != nil {
		logger.Error(err.Error(), nil)
		return err
	}
	if err := rbacHandler.createServiceAccount(&rbacResources.serviceAccount); err != nil {
		logger.Error(err.Error(), nil)
		return err
	}
	if len(rbacResources.clusterRoles) > 0 {
		for _, clusterRole := range rbacResources.clusterRoles {
			if err := rbacHandler.createClusterRole(&clusterRole); err != nil {
				logger.Error(err.Error(), nil)
				return err
			}
		}
	}
	for _, clusterRoleBinding := range rbacResources.clusterRoleBindings {
		if err := rbacHandler.createClusterRoleBinding(&clusterRoleBinding); err != nil {
			logger.Error(err.Error(), nil)
			return err
		}
	}
	return nil
}

func (rh *RBACHandler) getAndCheckSA(saName string) (*apicorev1.ServiceAccount, error) {
	saDetails, err := rh.coreClientSet.ServiceAccounts("default").Get(saName, metav1.GetOptions{})
	if err != nil {
		return nil, emperror.Wrap(err, "unable to get ServiceAccount details")
	}
	if label, ok := saDetails.ObjectMeta.Labels[defautlLabelKey]; !ok || label != defaultLabel[defautlLabelKey] {
		return nil, emperror.WrapWith(errors.New("label mismatch in serviceaccount"),
			"getting not jwt-to-rbac generated ServiceAccount is forbidden",
			defautlLabelKey, defaultLabel[defautlLabelKey],
			"service_account", saName)
	}
	return saDetails, nil
}

func (rh *RBACHandler) getAndCheckCRole(CRName string) error {
	cRole, err := rh.rbacClientSet.ClusterRoles().Get(CRName, metav1.GetOptions{})
	if err == nil {
		if label, ok := cRole.ObjectMeta.Labels[defautlLabelKey]; !ok || label != defaultLabel[defautlLabelKey] {
			return emperror.WrapWith(errors.New("label mismatch in clusterrole"),
				"there is a ClusterRole without required label",
				defautlLabelKey, defaultLabel[defautlLabelKey],
				"cluster_role", CRName)
		}
		return nil
	}
	return err
}

func (rh *RBACHandler) getAndCheckCRoleBinding(CRBindingName string) error {
	cRoleBind, err := rh.rbacClientSet.ClusterRoleBindings().Get(CRBindingName, metav1.GetOptions{})
	if err == nil {
		if label, ok := cRoleBind.ObjectMeta.Labels[defautlLabelKey]; !ok || label != defaultLabel[defautlLabelKey] {
			return emperror.WrapWith(errors.New("label mismatch in clusterrole"),
				"there is a ClusterRoleBinding without required label",
				defautlLabelKey, defaultLabel[defautlLabelKey],
				"cluster_rolebinding", CRBindingName)
		}
		return nil
	}
	return err
}

func (rh *RBACHandler) getSAReference(saName string) ([]metav1.OwnerReference, error) {
	saDetails, err := rh.getAndCheckSA(saName)
	if err != nil {
		return nil, err
	}
	owner := metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "ServiceAccount",
		Name:       saName,
		UID:        saDetails.ObjectMeta.UID,
	}

	return []metav1.OwnerReference{owner}, nil
}

func (rh *RBACHandler) removeServiceAccount(saName string, logger logur.Logger) error {
	if _, err := rh.getAndCheckSA(saName); err != nil {
		return err
	}
	err := rh.coreClientSet.ServiceAccounts("default").Delete(saName, &metav1.DeleteOptions{})
	if err != nil {
		return emperror.WrapWith(err, "unable to delete ServiceAccount", "service_account", saName)
	}
	return nil
}

// DeleteRBAC deletes RBAC resources
func DeleteRBAC(saName string, config *Config, logger logur.Logger) error {
	rbacHandler, err := NewRBACHandler(config.KubeConfig, logger)
	if err != nil {
		return err
	}
	if err := rbacHandler.removeServiceAccount(saName, logger); err != nil {
		logger.Error(err.Error(), nil)
		return err
	}
	return nil
}

// GetK8sToken getting serviceaccount secrets data
func GetK8sToken(saName string, config *Config, logger logur.Logger) ([]*SACredential, error) {
	rbacHandler, err := NewRBACHandler(config.KubeConfig, logger)
	if err != nil {
		return nil, err
	}

	saCreds, err := rbacHandler.listSACredentials(saName)
	if err != nil {
		return nil, err
	}

	return saCreds, nil
}

func (rh *RBACHandler) listSACredentials(saName string) ([]*SACredential, error) {
	saDetails, err := rh.getAndCheckSA(saName)
	if err != nil {
		return nil, err
	}
	var saCreds []*SACredential
	for _, secrets := range saDetails.Secrets {
		secret, err := rh.getSecret(secrets.Name)
		if err != nil {
			return nil, err
		}
		saCred := &SACredential{
			Name: secrets.Name,
			Data: secret.Data,
		}
		saCreds = append(saCreds, saCred)
	}

	return saCreds, nil
}

func (rh *RBACHandler) getSecret(name string) (*apicorev1.Secret, error) {
	secret, err := rh.coreClientSet.Secrets("default").Get(name, metav1.GetOptions{})
	if err != nil {
		return nil, emperror.With(err, "secret", name)
	}
	return secret, nil
}

func calculateDeleteTime(ttl string) (string, error) {
	dur, err := time.ParseDuration(ttl)
	if err != nil {
		return "", emperror.Wrap(err, "ttl parse failed")
	}
	return time.Now().Add(dur).Format(time.RFC3339), nil
}

func (rh *RBACHandler) createSecret(saName string, ttl string) (*apicorev1.Secret, error) {
	saDetails, err := rh.getAndCheckSA(saName)
	if err != nil {
		return nil, err
	}
	deleteTime, err := calculateDeleteTime(ttl)
	if err != nil {
		return nil, err
	}
	secretName := saName + tokenRandString(5)
	secretObj := &apicorev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: saDetails.Namespace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": saName,
				"banzaicloud.io/timetolive":          deleteTime,
			},
			Labels: defaultLabel,
		},
		Type: "kubernetes.io/service-account-token",
	}
	secret, err := rh.coreClientSet.Secrets("default").Create(secretObj)
	if err != nil {
		return nil, emperror.WrapWith(err, "create secret failed", "secretName", secretName)
	}

	return secret, nil
}

// CreateSAToken creates service account token with ttl
func CreateSAToken(saName string, config *Config, ttl string, logger logur.Logger) (*SACredential, error) {
	rbacHandler, err := NewRBACHandler(config.KubeConfig, logger)
	if err != nil {
		return nil, err
	}
	secret, err := rbacHandler.createSecret(saName, ttl)
	if err != nil {
		return nil, err
	}
	secretName := secret.GetName()
	secretData, err := func() (map[string][]byte, error) {
		timeout := time.After(5 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		for {
			select {
			case <-timeout:
				return nil, emperror.With(errors.New("timeout getting secret"), "secret_name", secretName)
			case <-ticker.C:
				secret, err := rbacHandler.getSecret(secretName)
				if err != nil {
					return nil, err
				}
				if secret.Data != nil {
					return secret.Data, nil
				}
			}
		}
	}()
	if err != nil {
		return nil, err
	}

	return &SACredential{Name: secretName, Data: secretData}, nil
}

func tokenRandString(n int) string {
	letterRunes := []rune("0123456789abcdefghijklmnopqrstuvwxyz")
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]rune, n)
	l := len(letterRunes)
	for i := range b {
		b[i] = letterRunes[seededRand.Intn(l)]
	}
	return "-token-" + string(b)
}
