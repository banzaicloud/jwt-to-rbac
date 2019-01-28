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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/banzaicloud/jwt-to-rbac/internal/config"
	"github.com/banzaicloud/jwt-to-rbac/internal/errorhandler"
	"github.com/banzaicloud/jwt-to-rbac/internal/log"
	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/goph/emperror"
	"github.com/goph/logur"
)

var logger logur.Logger
var errorHandler emperror.Handler

func init() {

	logConfig := log.Config{Format: "json", Level: "4", NoColor: true}
	logger = log.NewLogger(logConfig)
	logger = log.WithFields(logger, map[string]interface{}{"package": "main"})

	errorHandler = errorhandler.New(logger)
	defer emperror.HandleRecover(errorHandler)

	err := config.InitConfig()
	if err != nil {
		errorHandler.Handle(err)
	}
}

// GetHandler handles the index route
func GetHandler(w http.ResponseWriter, r *http.Request) {
	jsonBody, err := json.Marshal(rbachandler.ListClusterroleBindings())
	if err != nil {
		http.Error(w, "Error converting results to json",
			http.StatusInternalServerError)
	}
	w.Write(jsonBody)
}

// PostHandler converts post request body to string
func PostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body",
				http.StatusInternalServerError)
		}
		user, err := tokenhandler.Authorize(string(body))
		if err != nil {
			errorHandler.Handle(err)
		} else {
			b, _ := json.Marshal(user)
			w.Write(b)
			rbachandler.CreateRBAC(user)
		}
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func main() {

	logger.Info("configuration info", map[string]interface{}{
		"ClientID":   config.Configuration.ClientID,
		"IssuerURL":  config.Configuration.IssuerURL,
		"ServerPort": config.Configuration.ServerPort})

	mux := http.NewServeMux()
	mux.HandleFunc("/rbac", GetHandler)
	mux.HandleFunc("/token", PostHandler)
	err := http.ListenAndServe(":"+config.Configuration.ServerPort, mux)
	if err != nil {
		errorHandler.Handle(err)
		os.Exit(1)
	}
}
