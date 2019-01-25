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

	"github.com/banzaicloud/jwt-to-rbac/internal/errorhandler"
	"github.com/banzaicloud/jwt-to-rbac/internal/log"
	oidc "github.com/coreos/go-oidc"
	"github.com/goph/emperror"
	"github.com/goph/logur"
	"github.com/spf13/viper"
)

type Config struct {
	ClientID  string
	IssuerURL string
}

type User struct {
	Email  string
	Groups []string
}

var logger logur.Logger
var errorHandler emperror.Handler
var configuration Config

func init() {

	config := log.Config{Format: "json", Level: "4", NoColor: true}
	logger = log.NewLogger(config)
	logger = log.WithFields(logger, map[string]interface{}{"package": "tokenhandler"})

	errorHandler = errorhandler.New(logger)
	defer emperror.HandleRecover(errorHandler)

	viper.SetConfigName("config")
	viper.AddConfigPath("config")

	if err := viper.ReadInConfig(); err != nil {
		errorHandler.Handle(err)
	}
	err := viper.Unmarshal(&configuration)
	if err != nil {
		errorHandler.Handle(err)
	}

}

func initProvider() *oidc.IDTokenVerifier {
	// Initialize a provider by specifying dex's issuer URL.
	ctx := oidc.ClientContext(context.Background(), http.DefaultClient)
	provider, err := oidc.NewProvider(ctx, configuration.IssuerURL)
	if err != nil {
		errorHandler.Handle(err)
	}
	// Create an ID token parser, but only trust ID tokens issued to "example-app"
	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: configuration.ClientID})
	return idTokenVerifier
}

// Authorize verifies a bearer token and pulls user information form the claims.
func Authorize(bearerToken string) (*User, error) {
	idTokenVerifier := initProvider()
	idToken, err := idTokenVerifier.Verify(oidc.ClientContext(context.Background(), http.DefaultClient), bearerToken)
	if err != nil {
		return nil, emperror.With(err, "token", bearerToken)
	}
	// Extract custom claims.
	var claims struct {
		Email    string   `json:"email"`
		Verified bool     `json:"email_verified"`
		Groups   []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, emperror.Wrap(err, "failed to parse claims")
	}
	if !claims.Verified {
		return nil, emperror.With(errors.New("email in returned claims was not verified"), "claims.Email", claims.Email)
	}
	return &User{claims.Email, claims.Groups}, nil
}
