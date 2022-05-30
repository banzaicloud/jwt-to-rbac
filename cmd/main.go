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
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/goph/emperror"
	"github.com/oklog/run"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/banzaicloud/jwt-to-rbac/internal"
	"github.com/banzaicloud/jwt-to-rbac/internal/log"
	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
)

// nolint: gochecknoinits
func init() {
	pflag.Bool("version", false, "Show version information")
	pflag.Bool("dump-config", false, "Dump configuration to the console (and exit)")
	pflag.Bool("tokenhandler.insecure", false, "Use insecure connection")
}

func main() {
	Configure(viper.GetViper(), pflag.CommandLine)

	pflag.Parse()

	if viper.GetBool("version") {
		fmt.Printf("%s version %s (%s) built on %s\n", "jwt-to-rbac", Version, CommitHash, BuildDate)

		os.Exit(0)
	}

	err := viper.ReadInConfig()
	_, configFileNotFound := err.(viper.ConfigFileNotFoundError)
	if !configFileNotFound {
		emperror.Panic(errors.Wrap(err, "failed to read configuration"))
	}

	var config Config
	err = viper.Unmarshal(&config)
	emperror.Panic(errors.Wrap(err, "failed to unmarshal configuration"))

	if viper.GetBool("dump-config") {
		fmt.Printf("%+v\n", config)

		os.Exit(0)
	}

	// Create logger (first thing after configuration loading)
	logger := log.NewLogger(config.Log)

	// Provide some basic context to all log lines
	logger = log.WithFields(logger, map[string]interface{}{"service": "jwt-to-rbac"})

	if configFileNotFound {
		logger.Warn("configuration file not found", nil)
	}

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		logger.Info("Config file changed: " + e.Name)
		config = Config{}
		err = viper.Unmarshal(&config)
		emperror.Panic(errors.Wrap(err, "failed to unmarshal configuration"))
	})

	logger.Info("configuration info", map[string]interface{}{
		"ClientID":   config.Tokenhandler.OIDC.ClientID,
		"IssuerURL":  config.Tokenhandler.OIDC.IssuerURL,
		"ServerPort": config.App.Addr,
		"KubeConfig": config.Rbachandler.KubeConfig})

	var g run.Group
	{
		ln, _ := net.Listen("tcp", config.App.Addr)
		httpServer := &http.Server{Handler: internal.NewApp(&config.Tokenhandler, &config.Rbachandler, logger)}

		g.Add(
			func() error {
				logger.Info("Starting the HTTP server.")
				return httpServer.Serve(ln)
			},
			func(e error) {
				logger.Info("shutting server down")

				ctx := context.Background()
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
				defer cancel()

				err := httpServer.Shutdown(ctx)
				logger.Error("stop HTTP server due to error", map[string]interface{}{
					"error": err.Error(),
				})

				_ = httpServer.Close()
			},
		)
	}

	{
		var (
			cancelInterrupt = make(chan struct{})
			ch              = make(chan os.Signal, 2)
		)
		defer close(ch)

		g.Add(
			func() error {
				signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

				select {
				case sig := <-ch:
					logger.Info("captured signal", map[string]interface{}{"signal": sig})
				case <-cancelInterrupt:
				}

				return nil
			},
			func(e error) {
				close(cancelInterrupt)
				signal.Stop(ch)
			},
		)
	}

	{
		g.Add(
			func() error {
				logger.Info("Starting watching SA tokens.")
				return rbachandler.WatchSATokens(&config.Rbachandler, logger)
			},
			func(error) {
				logger.Error("unable to run the manager", map[string]interface{}{
					"error": err.Error(),
				})
				os.Exit(1)
			},
		)
	}

	{
		g.Add(
			func() error {
				logger.Info("Starting watching ClusterRoles.")
				return rbachandler.WatchClusterRoles(&config.Rbachandler, logger)
			},
			func(error) {
				logger.Error("unable to run the ClusterRoles watcher", map[string]interface{}{
					"error": err.Error(),
				})
				os.Exit(1)
			},
		)
	}

	if g.Run() != nil {
		logger.Error("unable to run the rungroup")
	}
}
