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
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/goph/logur"
)

// APIEndPoint for token handling
const APIEndPoint = "/tokens/"

const KubeconfigEndPoint = "/kubeconfig/"

// HTTPController collects the greeting use cases and exposes them as HTTP handlers.
type HTTPController struct {
	TConf     *tokenhandler.Config
	RConf     *rbachandler.Config
	Logger    logur.Logger
	authorize func(string, *tokenhandler.Config) (*tokenhandler.User, error)
}

var errForbidden = errors.New("ID token does not belong to the requested service account")

type tokenTTL struct {
	Duration string `json:"duration,omitempty"`
}

// NewHTTPHandler returns a new HTTP handler for the greeter.
func NewHTTPHandler(tconf *tokenhandler.Config, rconf *rbachandler.Config, logger logur.Logger) http.Handler {
	mux := http.NewServeMux()
	controller := NewHTTPController(tconf, rconf, logger)
	mux.HandleFunc(APIEndPoint, controller.handleSAcredential)
	mux.HandleFunc(KubeconfigEndPoint, controller.handleKubeconfig)
	return mux
}

// NewHTTPController returns a new HTTPController instance.
func NewHTTPController(tconf *tokenhandler.Config, rconf *rbachandler.Config, logger logur.Logger) *HTTPController {
	return &HTTPController{
		TConf:     tconf,
		RConf:     rconf,
		Logger:    logger,
		authorize: tokenhandler.Authorize,
	}
}

func bearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("missing Authorization header")
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", errors.New("invalid Authorization header, expected: Bearer <id-token>")
	}
	return strings.TrimSpace(parts[1]), nil
}

func (a *HTTPController) authenticate(r *http.Request, saName string) (int, error) {
	token, err := bearerToken(r)
	if err != nil {
		return http.StatusUnauthorized, err
	}
	user, err := a.authorize(token, a.TConf)
	if err != nil {
		a.Logger.Info("ID token validation failed", map[string]interface{}{"error": err.Error()})
		return http.StatusUnauthorized, errors.New("invalid ID token")
	}
	userSAName, err := rbachandler.ServiceAccountName(user)
	if err != nil {
		return http.StatusForbidden, err
	}
	if userSAName != saName {
		return http.StatusForbidden, errForbidden
	}
	return http.StatusOK, nil
}

func (a *HTTPController) authError(w http.ResponseWriter, status int, err error) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	http.Error(w, err.Error(), status)
}

func (a *HTTPController) handleSAcredential(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case "POST":
		if !a.RConf.EnableCreateSAToken {
			http.Error(w, "The method is disabled", http.StatusMethodNotAllowed)
			return
		}
		saName := r.URL.Path[len(APIEndPoint):]
		if status, err := a.authenticate(r, saName); err != nil {
			a.authError(w, status, err)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
		}
		ttl := tokenTTL{}
		err = json.Unmarshal(body, &ttl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		secretData, err := rbachandler.CreateSAToken(saName, a.RConf, ttl.Duration, a.Logger)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		b, _ := json.Marshal(secretData)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(b)

	case "GET":
		saName := r.URL.Path[len(APIEndPoint):]
		if status, err := a.authenticate(r, saName); err != nil {
			a.authError(w, status, err)
			return
		}
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

func (a *HTTPController) handleKubeconfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	saName := r.URL.Path[len(KubeconfigEndPoint):]
	if status, err := a.authenticate(r, saName); err != nil {
		a.authError(w, status, err)
		return
	}
	kubeconfig, err := rbachandler.GetKubeconfig(saName, a.RConf, a.Logger)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(kubeconfig)
}
