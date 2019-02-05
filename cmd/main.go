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
	"strconv"

	"github.com/banzaicloud/jwt-to-rbac/internal/app"
	"github.com/banzaicloud/jwt-to-rbac/internal/config"
	"github.com/banzaicloud/jwt-to-rbac/internal/log"
	"github.com/goph/emperror"
	"github.com/pkg/errors"
)

func main() {

	configuration, err := config.GetConfig()
	if err != nil {
		emperror.Panic(errors.Wrap(err, "failed to init get configuration"))
	}

	logConfig := log.Config{Format: configuration.Log.Format, Level: strconv.Itoa(configuration.Log.Level), NoColor: configuration.Log.NoColor}
	logger := log.NewLogger(logConfig)
	logger = log.WithFields(logger, map[string]interface{}{"package": "main"})

	logger.Info("configuration info", map[string]interface{}{
		"ClientID":   configuration.Dex.ClientID,
		"IssuerURL":  configuration.Dex.IssuerURL,
		"ServerPort": configuration.Server.Port,
		"KubeConfig": configuration.KubeConfig})

	app := &app.App{
		Mux:    &http.ServeMux{},
		Config: configuration,
		Logger: logger,
	}
	app.InitApp()
	app.Run()
}
