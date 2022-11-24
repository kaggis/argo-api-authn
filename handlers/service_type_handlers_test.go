package handlers

import (
	"bytes"
	"context"
	"github.com/ARGOeu/argo-api-authn/utils"
	LOGGER "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"net/http"
	"strings"
	"testing"
	"time"

	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/gorilla/mux"
	"net/http/httptest"
)

type ServiceTypeHandlersSuite struct {
	suite.Suite
}

// TestServiceTypeCreate tests the normal case of a service type creation
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreate() {

	postJSON := `{
	"name": "service1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token",
	"type": "ams"
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(201, w.Code)
	createdSer := servicetypes.ServiceType{}
	_ = json.Unmarshal([]byte(w.Body.String()), &createdSer)

	suite.Equal("service1", createdSer.Name)
	suite.Equal([]string{"127.0.0.1"}, createdSer.Hosts)
	suite.Equal([]string{"x509", "oidc"}, createdSer.AuthTypes)
	suite.Equal("api-key", createdSer.AuthMethod)
}

func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateWEBAPI() {

	postJSON := `{
	"name": "web-api-devel",
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509"],
	"auth_method": "headers",
	"type": "web-api"
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(201, w.Code)
	createdSer := servicetypes.ServiceType{}
	_ = json.Unmarshal([]byte(w.Body.String()), &createdSer)

	suite.Equal("web-api-devel", createdSer.Name)
	suite.Equal([]string{"127.0.0.1"}, createdSer.Hosts)
	suite.Equal([]string{"x509"}, createdSer.AuthTypes)
	suite.Equal("headers", createdSer.AuthMethod)
}

// TestServiceTypeCreateInvalidName tests the case where the service type's name already exists
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateInvalidName() {

	postJSON := `{
	"name": "s1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token",
    "type": "ams"
}`

	expRespJSON := `{
 "error": {
  "message": "service-type object with name: s1 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateEmptyHosts tests the case where the service type's hosts slice is empty
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateEmptyHosts() {

	postJSON := `{
	"name": "s1",
	"hosts": [],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token",
    "type": "ams"
}`

	expRespJSON := `{
 "error": {
  "message": "service-type object contains empty fields. empty value for field: hosts",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateEmptyType tests the case where the service type's type is empty
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateEmptyType() {

	postJSON := `{
	"name": "s1",
	"hosts": ["host1", "host2"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token",
    "type": ""
}`

	expRespJSON := `{
 "error": {
  "message": "service-type object contains empty fields. empty value for field: type",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateInvalidType tests the case where the service type's auth type is not supported
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateInvalidType() {

	postJSON := `{
	"name": "s1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token",
    "type": "unsup_type"
}`

	expRespJSON := `{
 "error": {
  "message": "type: unsup_type is not yet supported.Supported:[ams web-api custom]",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateInvalidAuthTypes tests the case where the service type's auth types are not yet supported
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateInvalidAuthTypes() {

	postJSON := `{
	"name": "s1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["unsup_type", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token",
    "type": "ams"
}`

	expRespJSON := `{
 "error": {
  "message": "auth_types: unsup_type is not yet supported.Supported:[x509 oidc]",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateInvalidAuthMethod tests the case where the service type's auth method are not yet supported
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateInvalidAuthMethod() {

	postJSON := `{
	"name": "s1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "unsup_method",
	"retrieval_field": "token",
    "type": "ams"
}`

	expRespJSON := `{
 "error": {
  "message": "auth_method: unsup_method is not yet supported.Supported:[api-key headers]",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateEmptyAuthTypes tests the case where the service type's auth types are empty
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateEmptyAuthTypes() {

	postJSON := `{
	"name": "s1",
	"hosts": ["127.0.0.1"],
	"auth_types": [],
	"auth_method": "api-key",
	"retrieval_field": "token",
    "type": "ams"
}`

	expRespJSON := `{
 "error": {
  "message": "auth_types: empty is not yet supported.Supported:[x509 oidc]",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())

}

// TestServiceTypeCreateInvalidJSON tests the case of the request containing an invalid json body
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateInvalidJSON() {

	postJSON := `{
	"name": "service1",
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token",
}`

	expResJSON := `{
 "error": {
  "message": "Poorly formatted JSON. invalid character '}' looking for beginning of object key string",
  "code": 400,
  "status": "BAD REQUEST"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(400, w.Code)
	suite.Equal(expResJSON, w.Body.String())
}

// TestServiceTypeCreateMissingField tests the case of the request containing an incomplete json body
func (suite *ServiceTypeHandlersSuite) TestServiceTypeCreateMissingField() {

	postJSON := `{
	"hosts": ["127.0.0.1"],
	"auth_types": ["x509", "oidc"],
	"auth_method": "api-key",
	"retrieval_field": "token"
}`

	expResJSON := `{
 "error": {
  "message": "service-type object contains empty fields. empty value for field: name",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expResJSON, w.Body.String())
}

// TestServiceTypeListOne tests the normal case
func (suite *ServiceTypeHandlersSuite) TestServiceTypeListOne() {

	expResJSON := `{
 "name": "s1",
 "hosts": [
  "host1",
  "host2",
  "host3"
 ],
 "auth_types": [
  "x509",
  "oidc"
 ],
 "auth_method": "api-key",
 "uuid": "uuid1",
 "created_on": "2018-05-05T18:04:05Z",
 "type": "ams"
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}", WrapConfig(ServiceTypesListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

// TestServiceTypeListOneNameCollision tests the case where two or more service types exist with the same name
func (suite *ServiceTypeHandlersSuite) TestServiceTypeListOneNameCollision() {

	expResJSON := `{
 "error": {
  "message": "Database Error: Multiple service-types with the same name: same_name",
  "code": 500,
  "status": "INTERNAL SERVER ERROR"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/same_name", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}", WrapConfig(ServiceTypesListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(500, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

// TestServiceTypeListOneNotFound tests the case where two or more service types exist with the same name
func (suite *ServiceTypeHandlersSuite) TestServiceTypeListOneNotFound() {

	expResJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/not_found", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}", WrapConfig(ServiceTypesListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

// TestServiceTypeListAll tests the normal functionality of listing all services types
func (suite *ServiceTypeHandlersSuite) TestServiceTypeListAll() {

	expResJSON := `{
 "service_types": [
  {
   "name": "s1",
   "hosts": [
    "host1",
    "host2",
    "host3"
   ],
   "auth_types": [
    "x509",
    "oidc"
   ],
   "auth_method": "api-key",
   "uuid": "uuid1",
   "created_on": "2018-05-05T18:04:05Z",
   "type": "ams"
  },
  {
   "name": "s2",
   "hosts": [
    "host3",
    "host4"
   ],
   "auth_types": [
    "x509"
   ],
   "auth_method": "headers",
   "uuid": "uuid2",
   "created_on": "2018-05-05T18:04:05Z",
   "type": "web-api"
  },
  {
   "name": "same_name",
   "hosts": null,
   "auth_types": null,
   "auth_method": "",
   "uuid": "",
   "created_on": "",
   "type": ""
  },
  {
   "name": "same_name",
   "hosts": null,
   "auth_types": null,
   "auth_method": "",
   "uuid": "",
   "created_on": "",
   "type": ""
  }
 ]
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types", nil)

	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

// TestsServiceListAllEmptyList tests the case of an empty service types list
func (suite *ServiceTypeHandlersSuite) TestServiceTypeListAllEmptyList() {

	expResJSON := `{
 "service_types": []
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// empty the store
	mockstore.ServiceTypes = []stores.QServiceType{}

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types", WrapConfig(ServiceTypeListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

// TestServiceTypeUpdate tests the normal case of a updating a service type - updates the name
func (suite *BindingHandlersSuite) TestServiceTypeUpdate() {

	postJSON := `{
	"name": "updated_name"
}`

	expRespJSON := `{
 "name": "updated_name",
 "hosts": [
  "host1",
  "host2",
  "host3"
 ],
 "auth_types": [
  "x509",
  "oidc"
 ],
 "auth_method": "api-key",
 "uuid": "uuid1",
 "created_on": "2018-05-05T18:04:05Z",
 "updated_on": "{{UPDATED_ON}}",
 "type": "ams"
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}", WrapConfig(ServiceTypeUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)

	qSt, _ := mockstore.QueryServiceTypes(context.Background(), "updated_name")
	expRespJSON = strings.Replace(expRespJSON, "{{UPDATED_ON}}", qSt[0].UpdatedOn, 1)
	// make sure the updated time is before now
	updatedTime, _ := time.Parse(utils.ZULU_FORM, qSt[0].UpdatedOn)
	suite.True(updatedTime.Before(time.Now().UTC()))
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestServiceTypeUpdateEmptyName tests case of updating a service type's name into an empty string
func (suite *BindingHandlersSuite) TestServiceTypeUpdateEmptyName() {

	postJSON := `{
	"name": ""
}`

	expRespJSON := `{
 "error": {
  "message": "service-type object contains empty fields. empty value for field: name",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-type/s1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-type/{service-type}", WrapConfig(ServiceTypeUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestServiceTypeUpdateEmptyAuthTypes tests the case of updating a service type's auth types into an empty slice
func (suite *BindingHandlersSuite) TestServiceTypeUpdateEmptyAuthTypes() {

	postJSON := `{
	"auth_types": []
}`

	expRespJSON := `{
 "error": {
  "message": "auth_types: empty is not yet supported.Supported:[x509 oidc]",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-type/s1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-type/{service-type}", WrapConfig(ServiceTypeUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestServiceTypeUpdateUnsupportedAuthType tests the case of updating a service type's auth type into something that not yet supported by the service
func (suite *BindingHandlersSuite) TestServiceTypeUpdateUnsupportedAuthType() {

	postJSON := `{
	"auth_types": ["unsup_auth"]
}`

	expRespJSON := `{
 "error": {
  "message": "auth_types: unsup_auth is not yet supported.Supported:[x509 oidc]",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-type/s1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-type/{service-type}", WrapConfig(ServiceTypeUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestServiceTypeUpdateUnsupportedAuthMethod tests the case of updating the auth method into something that's not yet supported
func (suite *BindingHandlersSuite) TestServiceTypeUpdateUnsupportedAuthMethod() {

	postJSON := `{
	"auth_method": "unsup_auth"
}`

	expRespJSON := `{
 "error": {
  "message": "auth_method: unsup_auth is not yet supported.Supported:[api-key headers]",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-type/s1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-type/{service-type}", WrapConfig(ServiceTypeUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestServiceTypeUpdateEmptyAuthMethod tests the case of updating the auth method an empty string
func (suite *BindingHandlersSuite) TestServiceTypeUpdateEmptyAuthMethod() {

	postJSON := `{
	"auth_method": ""
}`

	expRespJSON := `{
 "error": {
  "message": "service-type object contains empty fields. empty value for field: auth_method",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-type/s1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-type/{service-type}", WrapConfig(ServiceTypeUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestServiceTypeUpdateEmptyHosts tests the case of updating the hosts into an empty slice
func (suite *BindingHandlersSuite) TestServiceTypeUpdateEmptyHosts() {

	postJSON := `{
	"hosts": []
}`

	expRespJSON := `{
 "error": {
  "message": "service-type object contains empty fields. empty value for field: hosts",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-type/s1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-type/{service-type}", WrapConfig(ServiceTypeUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestServiceTypeUpdateNameAlreadyExists tests the case of updating the name into an already existing one
func (suite *BindingHandlersSuite) TestServiceTypeUpdateNameAlreadyExists() {

	postJSON := `{
	"name": "s2"
}`

	expRespJSON := `{
 "error": {
  "message": "service-type object with name: s2 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`
	req, err := http.NewRequest("PUT", "http://localhost:8080/service-type/s1", bytes.NewBuffer([]byte(postJSON)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-type/{service-type}", WrapConfig(ServiceTypeUpdate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestServiceTypeDeleteOe tests the normal case
func (suite *ServiceTypeHandlersSuite) TestServiceTypeDeleteOne() {

	req, err := http.NewRequest("DELETE", "http://localhost:8080/service-types/s1", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}", WrapConfig(ServiceTypeDeleteOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(204, w.Code)

}

// TestServiceTypeDeleteOneNotFound tests the case where the service doesn't exist
func (suite *ServiceTypeHandlersSuite) TestServiceTypeDeleteOneNotFound() {

	expResJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("DELETE", "http://localhost:8080/service-types/not_found", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}", WrapConfig(ServiceTypeDeleteOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expResJSON, w.Body.String())

}

func TestHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTypeHandlersSuite))
}
