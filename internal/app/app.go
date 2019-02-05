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

package app

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/goph/logur"

	"github.com/banzaicloud/jwt-to-rbac/internal/config"
	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
)

// App http application
type App struct {
	Mux    *http.ServeMux
	Config *config.Config
}

// InitApp initalize http application
func (a *App) InitApp() {
	a.Mux = http.NewServeMux()
	a.Mux.HandleFunc("/list", a.ListK8sResources)
	a.Mux.HandleFunc("/", a.CreateRBACfromJWT)
}

// Run serve http
func (a *App) Run(logger logur.Logger) {
	err := http.ListenAndServe(":"+a.Config.Server.Port, a.Mux)
	if err != nil {
		logger.Error(err.Error(), nil)
		os.Exit(1)
	}
}

// ListK8sResources listing ServiceAccounts
func (a *App) ListK8sResources(w http.ResponseWriter, r *http.Request) {
	rbacList, err := rbachandler.ListClusterroleBindings(a.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	jsonBody, err := json.Marshal(rbacList)
	if err != nil {
		http.Error(w, "Error converting results to json",
			http.StatusInternalServerError)
	}
	_, _ = w.Write(jsonBody)
}

// CreateRBACfromJWT converts JWT to K8s RBAC
func (a *App) CreateRBACfromJWT(w http.ResponseWriter, r *http.Request) {
	type jwtToken struct {
		Token string `json:"token"`
	}
	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)

		if err != nil {
			http.Error(w, "Error reading request body",
				http.StatusInternalServerError)
		}
		res := jwtToken{}
		err = json.Unmarshal(body, &res)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, err := tokenhandler.Authorize(res.Token, a.Config)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			b, _ := json.Marshal(user)
			_, _ = w.Write(b)
			err = rbachandler.CreateRBAC(user, a.Config)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}
