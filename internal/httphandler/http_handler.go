package httphandler

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/banzaicloud/jwt-to-rbac/pkg/rbachandler"
	"github.com/banzaicloud/jwt-to-rbac/pkg/tokenhandler"
	"github.com/goph/logur"
)

// HTTPController collects the greeting use cases and exposes them as HTTP handlers.
type HTTPController struct {
	TConf  *tokenhandler.Config
	RConf  *rbachandler.Config
	Logger logur.Logger
}

// NewHTTPHandler returns a new HTTP handler for the greeter.
func NewHTTPHandler(tconf *tokenhandler.Config, rconf *rbachandler.Config, logger logur.Logger) http.Handler {
	mux := http.NewServeMux()
	controller := NewHTTPController(tconf, rconf, logger)
	mux.HandleFunc("/list", controller.ListK8sResources)
	mux.HandleFunc("/remove/", controller.DeleteSA)
	mux.HandleFunc("/", controller.CreateRBACfromJWT)
	mux.HandleFunc("/secret/", controller.GetSAcredential)

	return mux
}

// NewHTTPController returns a new HTTPController instance.
func NewHTTPController(tconf *tokenhandler.Config, rconf *rbachandler.Config, logger logur.Logger) *HTTPController {
	return &HTTPController{
		TConf:  tconf,
		RConf:  rconf,
		Logger: logger,
	}
}

// ListK8sResources listing ServiceAccounts
func (a *HTTPController) ListK8sResources(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "GET" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	rbacList, err := rbachandler.ListRBACResources(a.RConf, a.Logger)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonBody, err := json.Marshal(rbacList)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jsonBody)
}

// CreateRBACfromJWT converts JWT to K8s RBAC
func (a *HTTPController) CreateRBACfromJWT(w http.ResponseWriter, r *http.Request) {
	type jwtToken struct {
		Token string `json:"token"`
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
	}
	res := jwtToken{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user, err := tokenhandler.Authorize(res.Token, a.TConf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		err = rbachandler.CreateRBAC(user, a.RConf, a.Logger)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b, _ := json.Marshal(user)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(b)
	}
}

// DeleteSA removes serviceaccount with its bindings
func (a *HTTPController) DeleteSA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "DELETE" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	saName := r.URL.Path[len("/remove/"):]
	if err := rbachandler.DeleteRBAC(saName, a.RConf, a.Logger); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// GetSAcredential get k8s token to sa
func (a *HTTPController) GetSAcredential(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "GET" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	saName := r.URL.Path[len("/secret/"):]
	secretData, err := rbachandler.GetK8sToken(saName, a.RConf, a.Logger)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	b, _ := json.Marshal(secretData)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
