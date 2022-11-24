package routing

import (
	"net/http"

	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/handlers"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// API Object that holds routing information and the router itself
type API struct {
	Router *mux.Router // router Object reference
	Routes []APIRoute  // routes definitions list
}

// APIRoute Item describing an API route
type APIRoute struct {
	Name    string           // name of the route for description purposes
	Method  string           // GET, POST, PUT string literals
	Path    string           // API call path with urlVars included
	Handler http.HandlerFunc // Handler Function to be used
	Auth    bool             // whether it should use the auth handler
}

// NewRouting creates a new routing object including mux.Router and routes definitions
func NewRouting(routes []APIRoute, store stores.Store, config *config.Config) *API {
	// Create the api Object
	ar := API{}
	// Create a new router and reference him in API object
	ar.Router = mux.NewRouter().StrictSlash(false)
	// reference routes input in API object too keep info centralized
	ar.Routes = routes

	// For each route
	for _, route := range ar.Routes {

		// prepare handle wrappers
		var handler http.HandlerFunc

		handler = route.Handler

		handler = handlers.WrapLog(handler, route.Name)

		//  skip the auth handler for the requests that don't require authorization
		if route.Auth {
			handler = handlers.WrapAuth(handler, store)
		}

		handler = handlers.WrapConfig(handler, store, config)

		ar.Router.Methods(route.Method).
			PathPrefix("/v1").
			Path(route.Path).
			Handler(context.ClearHandler(handler))
	}

	log.WithFields(
		log.Fields{
			"type": "service_log",
		},
	).Infof("API Router initialized!")

	// Return reference to the API object
	return &ar
}

var ApiRoutes = []APIRoute{
	{"serviceTypes:Create", "POST", "/service-types", handlers.ServiceTypeCreate, true},
	{"serviceTypes:ListOne", "GET", "/service-types/{service-type}", handlers.ServiceTypesListOne, true},
	{"serviceTypes:DeleteOne", "DELETE", "/service-types/{service-type}", handlers.ServiceTypeDeleteOne, true},
	{"serviceTypes:ListOne", "PUT", "/service-types/{service-type}", handlers.ServiceTypeUpdate, true},
	{"serviceType:ListAll", "GET", "/service-types", handlers.ServiceTypeListAll, true},
	{"authMethod:Create", "POST", "/service-types/{service-type}/authm", handlers.AuthMethodCreate, true},
	{"authMethod:ListOne", "GET", "/service-types/{service-type}/hosts/{host}/authm", handlers.AuthMethodListOne, true},
	{"authMethod:Delete", "DELETE", "/service-types/{service-type}/hosts/{host}/authm", handlers.AuthMethodDeleteOne, true},
	{"authMethod:Update", "PUT", "/service-types/{service-type}/hosts/{host}/authm", handlers.AuthMethodUpdateOne, true},
	{"bindings:ListAllByServiceTypeAndHost", "GET", "/service-types/{service-type}/hosts/{host}/bindings", handlers.BindingListAllByServiceTypeAndHost, true},
	{"authMethod:ListAll", "GET", "/authm", handlers.AuthMethodListAll, true},
	{"bindings:Create", "POST", "/bindings/{name}", handlers.BindingCreate, true},
	{"bindings:ListAll", "GET", "/bindings", handlers.BindingListAll, true},
	{"bindings:Update", "PUT", "/bindings/{name}", handlers.BindingUpdate, true},
	{"bindings:ListOneByName", "GET", "/bindings/{name}", handlers.BindingListOneByName, true},
	{"bindings:Delete", "DELETE", "/bindings/{name}", handlers.BindingDelete, true},
	{"auth:Map", "GET", "/service-types/{service-type}/hosts/{host}:authx509", handlers.AuthViaCert, false},
}
