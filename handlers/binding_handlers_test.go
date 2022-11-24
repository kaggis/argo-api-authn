package handlers

import (
	"bytes"
	"context"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	LOGGER "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"net/http"
	"strings"
	"testing"
	"time"

	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/bindings"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http/httptest"
)

type BindingHandlersSuite struct {
	suite.Suite
}

// TestBindingCreate tests the normal case of a binding creation
func (suite *BindingHandlersSuite) TestBindingCreate() {

	postJSON := `{
	"service_uuid": "uuid1",
    "host": "host1",
    "auth_identifier": "test_dn",
    "unique_key": "uni_key",
    "auth_type": "x509"
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings/new_binding", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(201, w.Code)
	createdBind := bindings.Binding{}
	_ = json.Unmarshal([]byte(w.Body.String()), &createdBind)

	suite.Equal("uuid1", createdBind.ServiceUUID)
	suite.Equal("host1", createdBind.Host)
	suite.Equal("new_binding", createdBind.Name)
	suite.Equal("test_dn", createdBind.AuthIdentifier)
	suite.Equal("uni_key", createdBind.UniqueKey)
	suite.Equal("x509", createdBind.AuthType)
}

// TestBindingCreateInvalidJSON tests the case where the request body is not a vlaid json
func (suite *BindingHandlersSuite) TestBindingCreateInvalidJSON() {

	postJSON := `{
	"service_uuid": "uuid1",
    "host": "host1",
    "auth_identifier": "test_dn",
    "unique_key": "uni_key"
`

	expRespJSON := `{
 "error": {
  "message": "Poorly formatted JSON. unexpected EOF",
  "code": 400,
  "status": "BAD REQUEST"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(400, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestBindingCreateMissingFieldServiceUUID tests the case where the binding doesn't contain the service_uuid field
func (suite *BindingHandlersSuite) TestBindingCreateMissingFieldServiceUUID() {

	postJSON := `{
    "host": "host1",
    "auth_identifier": "test_dn",
    "unique_key": "uni_key"
}`

	expRespJSON := `{
 "error": {
  "message": "binding object contains empty fields. empty value for field: service_uuid",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestBindingCreateMissingFieldHost tests the case where the binding doesn't contain the host field
func (suite *BindingHandlersSuite) TestBindingCreateMissingFieldHost() {

	postJSON := `{
	"service_uuid": "uuid1",
    "auth_identifier": "test_dn",
    "unique_key": "uni_key"
}`

	expRespJSON := `{
 "error": {
  "message": "binding object contains empty fields. empty value for field: host",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestBindingCreateMissingFieldAuthID tests the case where the binding doesn't contain the auth_identifier field
func (suite *BindingHandlersSuite) TestBindingCreateMissingFieldAuthID() {

	postJSON := `{
	"service_uuid": "uuid1",
    "host": "host1",
    "unique_key": "uni_key"
}`

	expRespJSON := `{
 "error": {
  "message": "binding object contains empty fields. empty value for field: auth_identifier",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestBindingCreateMissingFieldUniqueKey tests the case where the binding doesn't contain the service_uuid field
func (suite *BindingHandlersSuite) TestBindingCreateMissingFieldUniqueKey() {

	postJSON := `{
    "service_uuid": "uuid1",
    "host": "host1",
    "auth_identifier": "test_dn",
    "auth_type": "x509"
}`

	expRespJSON := `{
 "error": {
  "message": "binding object contains empty fields. empty value for field: unique_key",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingCreateUnknownService tests the case where the service uuid is not known
func (suite *BindingHandlersSuite) TestBindingCreateUnknownService() {

	postJSON := `{
    "service_uuid": "unknown",
    "host": "host1",
    "auth_identifier": "test_dn",
    "auth_type": "x509",
    "unique_key":"key1"
}`

	expRespJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingCreateUnknownHost tests the case where the host is not known to the specified service
func (suite *BindingHandlersSuite) TestBindingCreateUnknownHost() {

	postJSON := `{
    "service_uuid": "uuid1",
    "host": "unknown",
    "auth_identifier": "test_dn",
    "auth_type": "x509",
    "unique_key":"key1"
}`

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingCreateDNAlreadyExists tests the case where the given dn is already used by another binding
func (suite *BindingHandlersSuite) TestBindingCreateDNAlreadyExists() {

	postJSON := `{
    "service_uuid": "uuid1",
    "host": "host1",
    "auth_identifier": "test_dn_1",
    "unique_key":"key1",
    "auth_type": "x509"
}`

	expRespJSON := `{
 "error": {
  "message": "binding object with auth_identifier: test_dn_1 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingCreateNameAlreadyExists tests the case where the given name is already used by another binding
func (suite *BindingHandlersSuite) TestBindingCreateNameAlreadyExists() {

	postJSON := `{
    "service_uuid": "uuid1",
    "host": "host1",
    "auth_identifier": "test_dn_4",
    "unique_key":"key1",
    "auth_type": "x509"
}`

	expRespJSON := `{
 "error": {
  "message": "binding object with name: b1 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAll tests the normal case
func (suite *BindingHandlersSuite) TestBindingListAll() {

	expRespJSON := `{
 "bindings": [
  {
   "name": "b1",
   "service_uuid": "uuid1",
   "host": "host1",
   "uuid": "b_uuid1",
   "auth_identifier": "test_dn_1",
   "unique_key": "unique_key_1",
   "auth_type": "x509",
   "created_on": "2018-05-05T15:04:05Z"
  },
  {
   "name": "b2",
   "service_uuid": "uuid1",
   "host": "host1",
   "uuid": "b_uuid2",
   "auth_identifier": "test_dn_2",
   "unique_key": "unique_key_2",
   "auth_type": "x509",
   "created_on": "2018-05-05T15:04:05Z"
  },
  {
   "name": "b3",
   "service_uuid": "uuid1",
   "host": "host2",
   "uuid": "b_uuid3",
   "auth_identifier": "test_dn_3",
   "unique_key": "unique_key_3",
   "auth_type": "x509",
   "created_on": "2018-05-05T15:04:05Z"
  },
  {
   "name": "b4",
   "service_uuid": "uuid2",
   "host": "host3",
   "uuid": "b_uuid4",
   "auth_identifier": "test_dn_1",
   "unique_key": "unique_key_1",
   "auth_type": "x509",
   "created_on": "2018-05-05T15:04:05Z"
  }
 ]
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/bindings", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAll tests the normal case
func (suite *BindingHandlersSuite) TestBindingListAllByServiceTypeAndHost() {

	expRespJSON := `{
 "bindings": [
  {
   "name": "b1",
   "service_uuid": "uuid1",
   "host": "host1",
   "uuid": "b_uuid1",
   "auth_identifier": "test_dn_1",
   "unique_key": "unique_key_1",
   "auth_type": "x509",
   "created_on": "2018-05-05T15:04:05Z"
  },
  {
   "name": "b2",
   "service_uuid": "uuid1",
   "host": "host1",
   "uuid": "b_uuid2",
   "auth_identifier": "test_dn_2",
   "unique_key": "unique_key_2",
   "auth_type": "x509",
   "created_on": "2018-05-05T15:04:05Z"
  }
 ]
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/host1/bindings", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAllEmpty tests the empty case
func (suite *BindingHandlersSuite) TestBindingListAllEmpty() {

	expRespJSON := `{
 "bindings": []
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/bindings", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// empty the store
	mockstore.Bindings = []stores.QBinding{}

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings", WrapConfig(BindingListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAllByServiceTypeAndHostEmpty tests the empty case
func (suite *BindingHandlersSuite) TestBindingListAllByServiceTypeAndHostEmpty() {

	expRespJSON := `{
 "bindings": []
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/host1/bindings", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// empty the store
	mockstore.Bindings = []stores.QBinding{}

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAllByServiceTypeAndHostUnknownServiceType tests the case where the service type is unknown
func (suite *BindingHandlersSuite) TestBindingListAllByServiceTypeAndHostUnknownServiceType() {

	expRespJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/unknown_service/hosts/host1/bindings", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListAllByServiceTypeAndHostUnknownHost tests the case where the host is not known to the specified service
func (suite *BindingHandlersSuite) TestBindingListAllByServiceTypeAndHostUnknownHost() {

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/unknown_host/bindings", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByAuthID tests the normal case
func (suite *BindingHandlersSuite) TestBindingListOneByAuthID() {

	expRespJSON := `{
 "bindings": [
  {
   "name": "b1",
   "service_uuid": "uuid1",
   "host": "host1",
   "uuid": "b_uuid1",
   "auth_identifier": "test_dn_1",
   "unique_key": "unique_key_1",
   "auth_type": "x509",
   "created_on": "2018-05-05T15:04:05Z"
  }
 ]
}`

	req, err := http.NewRequest("GET",
		"http://localhost:8080/service-types/s1/hosts/host1/bindings?authID=test_dn_1", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByDNMultipleEntries tests case where two bindings with the same dn exist, under the same service type and host
func (suite *BindingHandlersSuite) TestBindingListOneByDNMultipleEntries() {

	expRespJSON := `{
 "error": {
  "message": "Database Error: More than 1 bindings found under the service type: uuid1 and host: host1 using the same AuthIdentifier: test_dn_1",
  "code": 500,
  "status": "INTERNAL SERVER ERROR"
 }
}`

	req, err := http.NewRequest("GET",
		"http://localhost:8080/service-types/s1/hosts/host1/bindings?authID=test_dn_1", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// add a binding that already exists
	binding1 := stores.QBinding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", AuthIdentifier: "test_dn_1", AuthType: "x509", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	mockstore.Bindings = append(mockstore.Bindings, binding1)

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(500, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByDnUnknownServiceType tests the case where the service type is unknown
func (suite *BindingHandlersSuite) TestBindingListOneByDnUnknownServiceType() {

	expRespJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/unknown_service/hosts/host1/bindings/test_dn_1", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByDnUnknownHost tests the case where the host is not known to the specified service
func (suite *BindingHandlersSuite) TestBindingListOneByDnUnknownHost() {

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/unknown_host/bindings/test_dn_1", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings/{dn}", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByDnUnknownDN tests the case where the dn doesn't match any binding under the host and service type
func (suite *BindingHandlersSuite) TestBindingListOneByDnUnknownDN() {

	expRespJSON := `{
 "error": {
  "message": "Binding was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET",
		"http://localhost:8080/service-types/s1/hosts/host1/bindings?authID=unknown_dn", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/bindings", WrapConfig(BindingListAllByServiceTypeAndHost, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByUUID tests the normal case
func (suite *BindingHandlersSuite) TestBindingListOneByUUID() {

	expRespJSON := `{
 "name": "b1",
 "service_uuid": "uuid1",
 "host": "host1",
 "uuid": "b_uuid1",
 "auth_identifier": "test_dn_1",
 "unique_key": "unique_key_1",
 "auth_type": "x509",
 "created_on": "2018-05-05T15:04:05Z"
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/bindings/b1", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingListOneByName, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingListOneByUUIDUnknownUUID tests the case where the provided UUID doesn't exist
func (suite *BindingHandlersSuite) TestBindingListOneByUUIDUnknownUUID() {

	expRespJSON := `{
 "error": {
  "message": "Binding was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/bindings/unknown_uuid", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{uuid}", WrapConfig(BindingListOneByName, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdate tests the normal case of a updating a binding - updates the name
func (suite *BindingHandlersSuite) TestBindingUpdate() {

	postJSON := `{
	"name": "updated_name"
}`

	expRespJSON := `{
 "name": "updated_name",
 "service_uuid": "uuid1",
 "host": "host1",
 "uuid": "b_uuid1",
 "auth_identifier": "test_dn_1",
 "unique_key": "unique_key_1",
 "auth_type": "x509",
 "created_on": "2018-05-05T15:04:05Z",
 "updated_on": "{{UPDATED_ON}}"
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)

	qB, _ := mockstore.QueryBindingsByUUIDAndName(context.Background(), "b_uuid1", "updated_name")
	expRespJSON = strings.Replace(expRespJSON, "{{UPDATED_ON}}", qB[0].UpdatedOn, 1)
	// make sure the updated time is before now
	updatedTime, _ := time.Parse(utils.ZULU_FORM, qB[0].UpdatedOn)
	suite.True(updatedTime.Before(time.Now().UTC()))

	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateServiceUUIDEmpty tests case of updating a binding's service_uuid into an empty string
func (suite *BindingHandlersSuite) TestBindingUpdateServiceUUIDEmpty() {

	postJSON := `{
	"service_uuid": ""
}`

	expRespJSON := `{
 "error": {
  "message": "binding object contains empty fields. empty value for field: service_uuid",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateHostEmpty tests case of updating a binding's host into an empty string
func (suite *BindingHandlersSuite) TestBindingUpdateHostEmpty() {

	postJSON := `{
	"host": ""
}`

	expRespJSON := `{
 "error": {
  "message": "binding object contains empty fields. empty value for field: host",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateUniqueKeyEmpty tests case of updating a binding's unique key into an empty string
func (suite *BindingHandlersSuite) TestBindingUpdateUniqueKeyEmpty() {

	postJSON := `{
	"unique_key": ""
}`

	expRespJSON := `{
 "error": {
  "message": "binding object contains empty fields. empty value for field: unique_key",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateDNEmpty tests case of updating a binding's dn into an empty string
func (suite *BindingHandlersSuite) TestBindingUpdateDNEmpty() {

	postJSON := `{
	"auth_identifier": ""
}`

	expRespJSON := `{
 "error": {
  "message": "binding object contains empty fields. empty value for field: auth_identifier",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateUnknownHost tests case of updating a binding's host into an unknown host
func (suite *BindingHandlersSuite) TestBindingUpdateUnknownHost() {

	postJSON := `{
	"host": "unknown"
}`

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateUnknownServiceUUID tests case of updating a binding's service type uuid into an unknown service type uuid
func (suite *BindingHandlersSuite) TestBindingUpdateUnknownServiceUUID() {

	postJSON := `{
	"service_uuid": "unknown"
}`

	expRespJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateInvalidJSON tests case of updating a binding using an invalid json
func (suite *BindingHandlersSuite) TestBindingUpdateInvalidJSON() {

	postJSON := `{
	"service_uuid": "uuid2"
` // missing closing bracket

	expRespJSON := `{
 "error": {
  "message": "Poorly formatted JSON. unexpected EOF",
  "code": 400,
  "status": "BAD REQUEST"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(400, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateAuthIDAlreadyExists tests case of updating a binding's auth identifier into an already existing one
func (suite *BindingHandlersSuite) TestBindingUpdateAuthIDAlreadyExists() {

	postJSON := `{
	"auth_identifier": "test_dn_2"
}`

	expRespJSON := `{
 "error": {
  "message": "binding object with auth_identifier: test_dn_2 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateNameAlreadyExists tests case of updating a binding's auth identifier into an already existing one
func (suite *BindingHandlersSuite) TestBindingUpdateNameAlreadyExists() {

	postJSON := `{
	"name": "b4"
}`

	expRespJSON := `{
 "error": {
  "message": "binding object with name: b4 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/b1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingUpdateUnknownUUID tests the case where the UUID doesn't exist
func (suite *BindingHandlersSuite) TestBindingUpdateUnknownUUID() {

	expRespJSON := `{
 "error": {
  "message": "Binding was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("PUT", "http://localhost:8080/bindings/unknown", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{uuid}", WrapConfig(BindingUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestBindingDelete tests the normal case
func (suite *BindingHandlersSuite) TestBindingDelete() {

	req, err := http.NewRequest("DELETE", "http://localhost:8080/bindings/b1", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{name}", WrapConfig(BindingDelete, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(204, w.Code)
}

// TestBindingDeleteUnknownHost tests the case where the given uuid is unknown
func (suite *BindingHandlersSuite) TestBindingDeleteUnknownDN() {

	expRespJSON := `{
 "error": {
  "message": "Binding was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("DELETE", "http://localhost:8080/bindings/unknown", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/bindings/{uuid}", WrapConfig(BindingDelete, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

func TestBindingHandlersSuite(t *testing.T) {
	LOGGER.SetOutput(ioutil.Discard)
	suite.Run(t, new(BindingHandlersSuite))
}
