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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
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

func appendCACertPoll(config *Config) (*http.Client, error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if config.CaCertPath != "" {
		certs, err := ioutil.ReadFile(config.CaCertPath)
		if err != nil {
			return nil, emperror.WrapWith(err, "Failed to append %q to RootCAs: %v", "cacertpath", config.CaCertPath)
		}
		_ = rootCAs.AppendCertsFromPEM(certs)
	}

	// Trust the augmented cert pool in our client
	httpConf := &tls.Config{
		InsecureSkipVerify: config.Insecure,
		RootCAs:            rootCAs,
	}
	tr := &http.Transport{TLSClientConfig: httpConf}
	return &http.Client{Transport: tr}, nil
}

func initProvider(config *Config) (*oidc.IDTokenVerifier, error) {
	// Initialize a provider by specifying dex's issuer URL.
	httpClient, err := appendCACertPoll(config)
	if err != nil {
		return nil, err
	}
	ctx := oidc.ClientContext(context.Background(), httpClient)
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
	if claims.FederatedClaims.ConnectorID == "" || claims.FederatedClaims.UserID == "" {
		return nil, emperror.Wrap(errors.New("jwt doesn't contain required federatedClaims"), "missing federatedClaims")
	}
	return &User{claims.Email, claims.Groups, claims.FederatedClaims}, nil
}
