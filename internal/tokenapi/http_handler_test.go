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
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/goph/logur"
	"github.com/stretchr/testify/assert"
)

const validToken = "valid.id.token"

func fakeAuthorize(token string, _ *tokenhandler.Config) (*tokenhandler.User, error) {
	if token != validToken {
		return nil, errors.New("invalid signature")
	}
	return &tokenhandler.User{
		Email: "janedoe@example.com",
		FederatedClaims: tokenhandler.FederatedClaims{
			ConnectorID: "ldap",
			UserID:      "cn=jane,ou=People,dc=example,dc=org",
		},
	}, nil
}

func newTestHandler(t *testing.T) http.Handler {
	rconf := &rbachandler.Config{
		KubeConfig:          filepath.Join(t.TempDir(), "missing-kubeconfig"),
		EnableCreateSAToken: true,
	}
	controller := NewHTTPController(&tokenhandler.Config{}, rconf, logur.NewNoopLogger())
	controller.authorize = fakeAuthorize
	mux := http.NewServeMux()
	mux.HandleFunc(APIEndPoint, controller.handleSAcredential)
	mux.HandleFunc(KubeconfigEndPoint, controller.handleKubeconfig)
	return mux
}

func TestHandleSAcredentialAuth(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		saName        string
		authorization string
		wantStatus    int
	}{
		{"get missing header", http.MethodGet, "janedoe-example-com", "", http.StatusUnauthorized},
		{"get wrong scheme", http.MethodGet, "janedoe-example-com", "Basic " + validToken, http.StatusUnauthorized},
		{"get empty bearer", http.MethodGet, "janedoe-example-com", "Bearer ", http.StatusUnauthorized},
		{"get invalid token", http.MethodGet, "janedoe-example-com", "Bearer bad.token", http.StatusUnauthorized},
		{"get other service account", http.MethodGet, "johndoe-example-com", "Bearer " + validToken, http.StatusForbidden},
		{"get own service account", http.MethodGet, "janedoe-example-com", "Bearer " + validToken, http.StatusNotFound},
		{"get lowercase scheme", http.MethodGet, "janedoe-example-com", "bearer " + validToken, http.StatusNotFound},
		{"post missing header", http.MethodPost, "janedoe-example-com", "", http.StatusUnauthorized},
		{"post other service account", http.MethodPost, "johndoe-example-com", "Bearer " + validToken, http.StatusForbidden},
		{"post own service account", http.MethodPost, "janedoe-example-com", "Bearer " + validToken, http.StatusNotFound},
	}
	handler := newTestHandler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, APIEndPoint+tt.saName, strings.NewReader(`{"duration": "1h"}`))
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, tt.wantStatus, rec.Code, rec.Body.String())
			if tt.wantStatus == http.StatusUnauthorized {
				assert.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestHandleSAcredentialRejectsUnverifiableToken(t *testing.T) {
	issuer := httptest.NewServer(http.NotFoundHandler())
	defer issuer.Close()
	tconf := &tokenhandler.Config{}
	tconf.OIDC.IssuerURL = issuer.URL
	tconf.OIDC.ClientID = "example-app"
	handler := NewHTTPHandler(tconf, &rbachandler.Config{}, logur.NewNoopLogger())

	req := httptest.NewRequest(http.MethodGet, APIEndPoint+"janedoe-example-com", nil)
	req.Header.Set("Authorization", "Bearer forged.id.token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleKubeconfigAuth(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		saName        string
		authorization string
		wantStatus    int
	}{
		{"missing header", http.MethodGet, "janedoe-example-com", "", http.StatusUnauthorized},
		{"invalid token", http.MethodGet, "janedoe-example-com", "Bearer bad.token", http.StatusUnauthorized},
		{"other service account", http.MethodGet, "johndoe-example-com", "Bearer " + validToken, http.StatusForbidden},
		{"own service account", http.MethodGet, "janedoe-example-com", "Bearer " + validToken, http.StatusNotFound},
		{"invalid method", http.MethodPost, "janedoe-example-com", "Bearer " + validToken, http.StatusMethodNotAllowed},
	}
	handler := newTestHandler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, KubeconfigEndPoint+tt.saName, nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, tt.wantStatus, rec.Code, rec.Body.String())
		})
	}
}
