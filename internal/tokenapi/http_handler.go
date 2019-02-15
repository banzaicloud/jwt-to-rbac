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

package tokenapi

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/goph/logur"
)

// APIEndPoint for token handling
const APIEndPoint = "/tokens/"

// HTTPController collects the greeting use cases and exposes them as HTTP handlers.
type HTTPController struct {
	RConf  *rbachandler.Config
	Logger logur.Logger
}

type tokenTTL struct {
	Duration string `json:"duration,omitempty"`
}

// NewHTTPHandler returns a new HTTP handler for the greeter.
func NewHTTPHandler(rconf *rbachandler.Config, logger logur.Logger) http.Handler {
	mux := http.NewServeMux()
	controller := NewHTTPController(rconf, logger)
	mux.HandleFunc(APIEndPoint, controller.handleSAcredential)
	return mux
}

// NewHTTPController returns a new HTTPController instance.
func NewHTTPController(rconf *rbachandler.Config, logger logur.Logger) *HTTPController {
	return &HTTPController{
		RConf:  rconf,
		Logger: logger,
	}
}

func (a *HTTPController) handleSAcredential(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case "POST":
		saName := r.URL.Path[len(APIEndPoint):]
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
		}
		ttl := tokenTTL{}
		err = json.Unmarshal(body, &ttl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		duration := ttl.Duration
		if ttl.Duration == "" {
			duration = a.RConf.TokenTTL
		}
		secretData, err := rbachandler.CreateSAToken(saName, a.RConf, duration, a.Logger)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		b, _ := json.Marshal(secretData)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(b)

	case "GET":
		saName := r.URL.Path[len(APIEndPoint):]
		secretData, err := rbachandler.GetK8sToken(saName, a.RConf, a.Logger)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		b, _ := json.Marshal(secretData)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)

	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
}
