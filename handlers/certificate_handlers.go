package handlers

import (
	"context"
	"net/http"

	"github.com/ARGOeu/argo-api-authn/metrics"

	"github.com/ARGOeu/argo-api-authn/auth"
	"github.com/ARGOeu/argo-api-authn/authmethods"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	gorillaContext "github.com/gorilla/context"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func AuthViaCert(w http.ResponseWriter, r *http.Request) {
	traceId := gorillaContext.Get(r, "trace_id").(string)
	rCTX := context.WithValue(context.Background(), "trace_id", traceId)

	var err error
	var ok bool
	var dataRes = make(map[string]interface{})
	var binding bindings.Binding
	var serviceType servicetypes.ServiceType
	var authm authmethods.AuthMethod

	//context references
	store := gorillaContext.Get(r, "stores").(stores.Store)

	// url vars
	vars := mux.Vars(r)
	cfg := gorillaContext.Get(r, "config").(config.Config)

	if len(r.TLS.PeerCertificates) == 0 {
		err = &utils.APIError{Message: "No certificate provided", Code: 400, Status: "BAD REQUEST"}
		utils.RespondError(rCTX, w, err)
		return
	}

	// validate the certificate
	if cfg.VerifyCertificate {
		if err = auth.ValidateClientCertificate(rCTX,
			r.TLS.PeerCertificates[0], r.RemoteAddr, cfg.ClientCertHostVerification); err != nil {
			utils.RespondError(rCTX, w, err)
			return
		}
	}

	// Find information regarding the requested serviceType
	if serviceType, err = servicetypes.FindServiceTypeByName(rCTX, vars["service-type"], store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// check if the service type wants to support external x509 authentication
	if err = serviceType.SupportsAuthType("x509"); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// check if the provided host is associated with the given serviceType type
	if ok = serviceType.HasHost(vars["host"]); ok == false {
		err = utils.APIErrNotFound("Host")
		utils.RespondError(rCTX, w, err)
		return
	}

	// check if the auth method exists
	if authm, err = authmethods.AuthMethodFinder(rCTX, serviceType.UUID, vars["host"], serviceType.AuthMethod, store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// Find the binding associated with the provided certificate
	rdnSequence := auth.ExtractEnhancedRDNSequenceToString(r.TLS.PeerCertificates[0])

	log.WithFields(
		log.Fields{
			"trace_id":     rCTX.Value("trace_id"),
			"type":         "service_log",
			"rdn":          rdnSequence,
			"service_type": serviceType.Name,
			"host":         vars["host"],
		},
	).Info("New Certificate request")

	if binding, err = bindings.FindBindingByAuthID(rCTX, rdnSequence, serviceType.UUID, vars["host"], "x509", store); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	if dataRes, err = authm.RetrieveAuthResource(rCTX, binding, serviceType, &cfg); err != nil {
		utils.RespondError(rCTX, w, err)
		return
	}

	// keep track of bindings/certificates without the IP SAN extension
	if !auth.HasIPSANs(r.TLS.PeerCertificates[0]) {
		err = metrics.TrackMissingCertificateIpSan(rCTX, binding, store)
		if err != nil {
			log.WithFields(
				log.Fields{
					"trace_id":     rCTX.Value("trace_id"),
					"type":         "service_log",
					"rdn":          rdnSequence,
					"service_type": serviceType.Name,
					"host":         vars["host"],
					"error":        err.Error(),
				},
			).Error("Error while tracking missing IP SAN extension")
		}
	}

	utils.RespondOk(w, 200, dataRes)
}
