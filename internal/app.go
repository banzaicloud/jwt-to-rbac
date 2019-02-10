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

package internal

import (
	"net/http"

	"github.com/banzaicloud/jwt-to-rbac/internal/httphandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/goph/logur"
)

// NewApp retunrs HTTPHandler
func NewApp(tconf *tokenhandler.Config, rconf *rbachandler.Config, logger logur.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", httphandler.NewHTTPHandler(tconf, rconf, logger))
	return mux
}
