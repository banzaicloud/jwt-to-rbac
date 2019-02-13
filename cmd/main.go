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

package main

import (
	"net/http"
	"os"

	"github.com/banzaicloud/jwt-to-rbac/internal"
	"github.com/banzaicloud/jwt-to-rbac/internal/log"
	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/goph/emperror"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

func main() {
	Configure(viper.GetViper())

	err := viper.ReadInConfig()
	_, configFileNotFound := err.(viper.ConfigFileNotFoundError)
	if !configFileNotFound {
		emperror.Panic(errors.Wrap(err, "failed to read configuration"))
	}

	var config Config
	err = viper.Unmarshal(&config)
	emperror.Panic(errors.Wrap(err, "failed to unmarshal configuration"))

	// Create logger (first thing after configuration loading)
	logger := log.NewLogger(config.Log)

	// Provide some basic context to all log lines
	logger = log.WithFields(logger, map[string]interface{}{"service": "jwt-to-rbac"})

	if configFileNotFound {
		logger.Warn("configuration file not found", nil)
	}

	logger.Info("configuration info", map[string]interface{}{
		"ClientID":   config.Tokenhandler.Dex.ClientID,
		"IssuerURL":  config.Tokenhandler.Dex.IssuerURL,
		"ServerPort": config.App.Addr,
		"KubeConfig": config.Rbachandler.KubeConfig,
		"Version":    Version,
		"CommitHash": CommitHash,
		"BuildDate":  BuildDate})

	go rbachandler.WatchSATokens(&config.Rbachandler, logger)

	mux := internal.NewApp(&config.Tokenhandler, &config.Rbachandler, logger)
	err = http.ListenAndServe(config.App.Addr, mux)
	if err != nil {
		logger.Error(err.Error(), nil)
		os.Exit(1)
	}
}
