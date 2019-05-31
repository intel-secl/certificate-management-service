// +build integration

package resource

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestReportResource(t *testing.T) {
	assert := assert.New(t)
	checkErr := func(e error) {
		assert.NoError(e)
		if e != nil {
			assert.FailNow("fatal error, cannot continue test")
		}
	}
	_, ci := os.LookupEnv("CI")
	var host string
	if ci {
		host = "postgres"
	} else {
		host = "localhost"
	}

	//flavor, err := "http://10.1.68.21:20080/v2/cms/ca-certificates"

	r := mux.NewRouter()
	SetReportsEndpoints(r.PathPrefix("/cms/ca-certificates").Subrouter())
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/cms/ca-certificates")
	req.Header.Add("Content-Type", "application/x-pem-file")
	req.Header.Add("Accept", "application/x-pem-file")
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusOK, recorder.Code)
}
