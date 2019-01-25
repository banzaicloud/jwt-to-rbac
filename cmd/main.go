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

	"github.com/banzaicloud/jwt-to-rbac/internal/errorhandler"
	"github.com/banzaicloud/jwt-to-rbac/internal/log"
	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/goph/emperror"
	"github.com/goph/logur"
	"github.com/spf13/viper"
)

// var kubeconfig string

type Config struct {
	ClientID  string
	IssuerURL string
}

var logger logur.Logger
var errorHandler emperror.Handler
var configuration Config

func init() {

	config := log.Config{Format: "json", Level: "4", NoColor: true}
	logger = log.NewLogger(config)
	logger = log.WithFields(logger, map[string]interface{}{"package": "main"})

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
		}
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func main() {

	logger.Info("configuration", map[string]interface{}{"ClientID": configuration.ClientID})
	logger.Info("configureation", map[string]interface{}{"IssuerURL": configuration.IssuerURL})

	mux := http.NewServeMux()
	mux.HandleFunc("/rbac", GetHandler)
	mux.HandleFunc("/token", PostHandler)

	logger.Info("Listening on :5555", nil)
	err := http.ListenAndServe(":5555", mux)
	if err != nil {
		errorHandler.Handle(err)
		os.Exit(1)
	}
}
