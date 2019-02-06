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

package config

import (
	"os"
	"strings"

	"github.com/goph/emperror"
	"github.com/spf13/viper"
)

type Config struct {
	Dex          Dex
	Server       Server
	CustomGroups []CustomGroup
	KubeConfig   string
	Log          Log
	APIServer    string
}

type Dex struct {
	ClientID  string
	IssuerURL string
}

type Server struct {
	Port int
}

type CustomGroup struct {
	GroupName   string
	CustomRules []CustomRule
}

type CustomRule struct {
	Verbs     []string
	Resources []string
	APIGroups []string
}

type Log struct {
	Level   int
	NoColor bool
	Format  string
}

// GetConfig get config
func GetConfig() (*Config, error) {
	var configuration Config

	viper.SetConfigName("config")
	viper.AddConfigPath("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(os.Getenv("CONFIG_DIR"))
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, emperror.Wrap(err, "read configuration failed")
	}
	err := viper.Unmarshal(&configuration)
	if err != nil {
		return &Config{}, emperror.Wrap(err, "unmarshal configuration failed")
	}
	return &configuration, nil
}
