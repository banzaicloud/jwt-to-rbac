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

package rbacapi

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/goph/logur"
)

// APIEndPoint for RBAC handling
const APIEndPoint = "/rbac/"

type jwtToken struct {
	Token string `json:"token"`
}

// HTTPController collects the greeting use cases and exposes them as HTTP handlers.
type HTTPController struct {
	TConf  *tokenhandler.Config
	RConf  *rbachandler.Config
	Logger logur.Logger
}

// NewHTTPHandler returns a new HTTP handler for the greeter.
func NewHTTPHandler(tconf *tokenhandler.Config, rconf *rbachandler.Config, logger logur.Logger) http.Handler {
	mux := http.NewServeMux()
	controller := NewHTTPController(tconf, rconf, logger)
	mux.HandleFunc(APIEndPoint, controller.handleRBACResources)

	return mux
}

// NewHTTPController returns a new HTTPController instance.
func NewHTTPController(tconf *tokenhandler.Config, rconf *rbachandler.Config, logger logur.Logger) *HTTPController {
	return &HTTPController{
		TConf:  tconf,
		RConf:  rconf,
		Logger: logger,
	}
}

func (a *HTTPController) handleRBACResources(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case "GET":
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

	case "POST":
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
			return
		}
		err = rbachandler.CreateRBAC(user, a.RConf, a.Logger)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b, _ := json.Marshal(user)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(b)

	case "DELETE":
		saName := r.URL.Path[len(APIEndPoint):]
		if err := rbachandler.DeleteRBAC(saName, a.RConf, a.Logger); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)

	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}
