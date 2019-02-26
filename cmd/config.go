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
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/banzaicloud/jwt-to-rbac/internal/log"
	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/spf13/viper"
)

type Config struct {
	// Dex configuration
	Tokenhandler tokenhandler.Config
	// rbachandler config
	Rbachandler rbachandler.Config
	// App configuration
	App struct {
		Addr string
	}
	// Log configuration
	Log log.Config
}

// Configure configures some defaults in the Viper instance.
func Configure(v *viper.Viper, p *pflag.FlagSet) {
	p.Init("jwt-to-rbac", pflag.ExitOnError)
	pflag.Usage = func() {
		_, _ = fmt.Fprintln(os.Stderr, "Usage of jwt-to-rbac:")
		pflag.PrintDefaults()
	}
	_ = v.BindPFlags(p)
	// Log configuration
	v.SetDefault("log.format", "json")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.noColor", true)
	v.SetDefault("rbachandler.tokenttl", "24h")
	v.SetDefault("tokenhandler.insecure", false)

	v.AllowEmptyEnv(true)
	v.SetEnvPrefix("jwttorbac")
	v.SetConfigName("config")
	v.AddConfigPath(".")
	v.AddConfigPath(os.Getenv("CONFIG_DIR"))
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
}
