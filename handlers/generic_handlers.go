package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/ARGOeu/argo-api-authn/version"
	gorillaContext "github.com/gorilla/context"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// WrapConfig handle wrapper to retrieve configuration
func WrapConfig(hfn http.HandlerFunc, store stores.Store, config *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// clone the store
		traceId := uuid.NewV4().String()
		gorillaContext.Set(r, "trace_id", traceId)
		gorillaContext.Set(r, "stores", store)
		gorillaContext.Set(r, "config", *config)
		gorillaContext.Set(r, "service_token", config.ServiceToken)
		hfn.ServeHTTP(w, r)

	})
}

//WrapAuth authorizes the user
func WrapAuth(hfn http.HandlerFunc, store stores.Store) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		urlQueryVars := r.URL.Query()
		serviceToken := gorillaContext.Get(r, "service_token").(string)
		if urlQueryVars.Get("key") != serviceToken {
			err := utils.APIErrUnauthorized("Wrong Credentials")
			traceId := gorillaContext.Get(r, "trace_id").(string)
			rCTX := context.WithValue(context.Background(), "trace_id", traceId)
			utils.RespondError(rCTX, w, err)
			return
		}
		hfn.ServeHTTP(w, r)
	})
}

// WrapLog handle wrapper to apply Logging
func WrapLog(hfn http.Handler, name string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		start := time.Now()

		log.WithFields(
			log.Fields{
				"type":     "request_log",
				"method":   r.Method,
				"path":     r.URL.Path,
				"action":   name,
				"trace_id": gorillaContext.Get(r, "trace_id"),
			},
		).Info("New Request accepted . . .")

		hfn.ServeHTTP(w, r)

		log.WithFields(
			log.Fields{
				"type":            "request_log",
				"method":          r.Method,
				"path":            r.URL.Path,
				"action":          name,
				"processing_time": time.Since(start).String(),
				"trace_id":        gorillaContext.Get(r, "trace_id"),
			},
		).Info("")

	})
}

// ListVersion displays version information about the service
func ListVersion(w http.ResponseWriter, r *http.Request) {

	// Add content type header to the response
	contentType := "application/json"
	charset := "utf-8"
	w.Header().Add("Content-Type", fmt.Sprintf("%s; charset=%s", contentType, charset))

	v := version.Version{
		BuildTime: version.BuildTime,
		GO:        version.GO,
		Compiler:  version.Compiler,
		OS:        version.OS,
		Arch:      version.Arch,
		Distro:    version.Distro,
	}

	urlQueryVars := r.URL.Query()
	serviceToken := gorillaContext.Get(r, "service_token").(string)
	// Show the api release only for authorised requests
	if urlQueryVars.Get("key") == serviceToken {
		v.Release = version.Release
	}

	utils.RespondOk(w, http.StatusOK, v)
}

// HealthCheck just returns when the service is up and running
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	utils.RespondOk(w, http.StatusOK, nil)
}
