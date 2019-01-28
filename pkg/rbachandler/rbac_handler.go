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

	"github.com/banzaicloud/jwt-to-rbac/internal/log"
	"github.com/goph/emperror"
	"github.com/goph/logur"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbacv1 "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var kubeconfig string
var logger logur.Logger

func init() {
	// flag.StringVar(&kubeconfig, "", "", "path to Kubernetes config file")
	flag.StringVar(&kubeconfig, "kubeconfig", "/Users/poke/.kube/config", "path to Kubernetes config file")
	flag.Parse()

	logConfig := log.Config{Format: "json", Level: "4", NoColor: true}
	logger = log.NewLogger(logConfig)
	logger = log.WithFields(logger, map[string]interface{}{"package": "rbachandler"})

}

func getConfig() (*rest.Config, error) {
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
	config, err := getConfig()
	if err != nil {
		logger.Error("failed to get k8s cluster config", map[string]interface{}{"error": err})
	}
	rbacConfig, _ := rbacv1.NewForConfig(config)
	bindings := rbacConfig.ClusterRoleBindings()
	binds, _ := bindings.List(metav1.ListOptions{})
	var rbacList []string
	for _, b := range binds.Items {
		rbacList = append(rbacList, b.GetName())
	}

	return rbacList
}

// CreateServiceAccount create serviceaccount
func CreateServiceAccount() {

}

// BindClusterRoleToServiceAccount bind role to serviceaccount
func BindClusterRoleToServiceAccount() {

}

func checkClusterRole() {

}
