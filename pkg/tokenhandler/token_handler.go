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

package tokenhandler

import (
	"context"
	"errors"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"github.com/goph/emperror"
)

// FederatedClaims dex
type FederatedClaims struct {
	ConnectorID string `json:"connector_id"`
	UserID      string `json:"user_id"`
}

// User impelements generateServiceAccount
type User struct {
	Email           string
	Groups          []string
	FederatedClaims FederatedClaims
}

func initProvider(config *Config) (*oidc.IDTokenVerifier, error) {
	// Initialize a provider by specifying dex's issuer URL.
	ctx := oidc.ClientContext(context.Background(), http.DefaultClient)
	provider, err := oidc.NewProvider(ctx, config.Dex.IssuerURL)
	if err != nil {
		return nil, emperror.WrapWith(err, "provider init failed", "issuerURL", config.Dex.IssuerURL)
	}
	// Create an ID token parser, but only trust ID tokens issued to "ClientID"
	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: config.Dex.ClientID})
	return idTokenVerifier, nil
}

// Authorize verifies a bearer token and pulls user information form the claims.
func Authorize(bearerToken string, config *Config) (*User, error) {
	idTokenVerifier, err := initProvider(config)
	if err != nil {
		return nil, err
	}
	idToken, err := idTokenVerifier.Verify(oidc.ClientContext(context.Background(), http.DefaultClient), bearerToken)
	if err != nil {
		return nil, emperror.With(err, "token", bearerToken)
	}

	// Extract custom claims.
	var claims struct {
		Email           string          `json:"email"`
		Verified        bool            `json:"email_verified"`
		Groups          []string        `json:"groups"`
		FederatedClaims FederatedClaims `json:"federated_claims"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, emperror.Wrap(err, "failed to parse claims")
	}
	if !claims.Verified {
		return nil, emperror.With(errors.New("email in returned claims was not verified"), "claims.Email", claims.Email)
	}
	return &User{claims.Email, claims.Groups, claims.FederatedClaims}, nil
}
