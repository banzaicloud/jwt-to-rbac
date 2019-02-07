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

package internal

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/goph/logur"
)

// App http application
type App struct {
	Mux    *http.ServeMux
	TConf  *tokenhandler.Config
	RConf  *rbachandler.Config
	Logger logur.Logger
}

// InitApp initalize http application
func (a *App) InitApp() {
	a.Mux = http.NewServeMux()
	a.Mux.HandleFunc("/list", a.ListK8sResources)
	a.Mux.HandleFunc("/remove/", a.DeleteSA)
	a.Mux.HandleFunc("/", a.CreateRBACfromJWT)
	a.Mux.HandleFunc("/secret/", a.GetSAcredential)
}

// ListK8sResources listing ServiceAccounts
func (a *App) ListK8sResources(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "GET" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	rbacList, err := rbachandler.ListRBACResources(a.RConf, a.Logger)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonBody, err := json.Marshal(rbacList)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jsonBody)
}

// CreateRBACfromJWT converts JWT to K8s RBAC
func (a *App) CreateRBACfromJWT(w http.ResponseWriter, r *http.Request) {
	type jwtToken struct {
		Token string `json:"token"`
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
	}
	res := jwtToken{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user, err := tokenhandler.Authorize(res.Token, a.TConf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		err = rbachandler.CreateRBAC(user, a.RConf, a.Logger)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b, _ := json.Marshal(user)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(b)
	}
}

// DeleteSA removes serviceaccount with its bindings
func (a *App) DeleteSA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "DELETE" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	saName := r.URL.Path[len("/remove/"):]
	if err := rbachandler.DeleteRBAC(saName, a.RConf, a.Logger); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// GetSAcredential get k8s token to sa
func (a *App) GetSAcredential(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "GET" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	saName := r.URL.Path[len("/secret/"):]
	secretData, err := rbachandler.GetK8sToken(saName, a.RConf, a.Logger)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	b, _ := json.Marshal(secretData)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
