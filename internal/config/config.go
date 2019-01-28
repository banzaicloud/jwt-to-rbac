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

	"github.com/goph/emperror"
	"github.com/spf13/viper"
)

type config struct {
	ClientID   string
	IssuerURL  string
	ServerPort string
}

// Configuration struct
var Configuration config

// InitConfig get config
func InitConfig() error {

	viper.SetConfigName("config")
	viper.AddConfigPath("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(os.Getenv("CONFIG_DIR"))

	if err := viper.ReadInConfig(); err != nil {
		return emperror.Wrap(err, "read configuration failed")
	}
	err := viper.Unmarshal(&Configuration)
	if err != nil {
		return emperror.Wrap(err, "unmarshal configuration failed")
	}
	return nil
}
