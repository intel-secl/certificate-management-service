package resource

import (
	"fmt"
	"intel/isecl/cms/version"
	"net/http"

	"github.com/gorilla/mux"
)

// SetVersionEndpoints installs route handler for GET /version
func SetVersionEndpoints(r *mux.Router) {
	r.HandleFunc("", getVersion).Methods("GET")
}

// GetVersion handles GET /version
func getVersion(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("%s-%s", version.Version, version.GitHash)))
}
