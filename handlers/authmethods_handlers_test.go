package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ARGOeu/argo-api-authn/authmethods"
	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	"github.com/gorilla/mux"
	LOGGER "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type AuthMethodsHandlersTestSuite struct {
	suite.Suite
}

// TestAuthMethodCreate tests the default case of creating an auth method of type api-key and service type of ams
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodCreate() {

	var expAm = &authmethods.ApiKeyAuthMethod{}

	reqBody := `{
 "access_key": "key1",
 "host": "host2",
 "port": 9000
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(201, w.Code)

	// unmarshal the response
	json.Unmarshal([]byte(w.Body.String()), expAm)
	suite.Equal("uuid1", expAm.ServiceUUID)
	suite.Equal("host2", expAm.Host)
	suite.Equal(9000, expAm.Port)
	suite.Equal("api-key", expAm.Type)
	suite.NotEqual("", expAm.UUID)
	suite.NotEqual("", expAm.CreatedOn)
}

// TestAuthMethodCreate tests the default case of creating an auth method of type api-key and service type of ams
func (suite *AuthMethodsHandlersTestSuite) TestHeadersAuthMethodCreate() {

	var expAm = &authmethods.HeadersAuthMethod{}

	reqBody := `{
 "headers": {"x-api-token": "token-1"},
 "host": "host3",
 "port": 9000
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s2/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()
	// empty the store
	mockstore.AuthMethods = []stores.QAuthMethod{}

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(201, w.Code)

	// unmarshal the response
	json.Unmarshal([]byte(w.Body.String()), expAm)
	suite.Equal("uuid2", expAm.ServiceUUID)
	suite.Equal("host3", expAm.Host)
	suite.Equal(9000, expAm.Port)
	suite.Equal("headers", expAm.Type)
	suite.Equal(map[string]string{"x-api-token": "token-1"}, expAm.Headers)
	suite.NotEqual("", expAm.UUID)
	suite.NotEqual("", expAm.CreatedOn)

}

// TestAuthMethodCreateOverrideDefaults tests the default case of creating an auth method of type api-key and service type of ams while overriding path and auth retrieval field
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodCreateOverrideDefaults() {

	var expAm = &authmethods.ApiKeyAuthMethod{}

	reqBody := `{
 "access_key": "key1",
 "host": "host2",
 "port": 9000,
 "path": "/some/other/{{identifier}}?key={{access_key}}",
 "retrieval_field": "some_token"
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(201, w.Code)

	// unmarshal the response
	json.Unmarshal([]byte(w.Body.String()), expAm)
	suite.Equal("uuid1", expAm.ServiceUUID)
	suite.Equal("host2", expAm.Host)
	suite.Equal(9000, expAm.Port)
	suite.NotEqual("", expAm.UUID)
	suite.NotEqual("", expAm.CreatedOn)
}

// TestAuthMethodCreateOverrideDefaultsServiceUUID tests the default case of creating an auth method of type api-key and service type of ams while overriding the service uuid WHICH shall not work
// the service uuid is assigned through the specified service on the request
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodCreateOverrideDefaultsServiceUUID() {

	var expAm = &authmethods.ApiKeyAuthMethod{}

	reqBody := `{
 "access_key": "key1",
 "host": "host3",
 "port": 9000,
 "service_uuid": "uuid2"
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(201, w.Code)

	// unmarshal the response
	json.Unmarshal([]byte(w.Body.String()), expAm)
	suite.Equal("uuid1", expAm.ServiceUUID) //uuid2 is being ignored
	suite.Equal("host3", expAm.Host)
	suite.Equal(9000, expAm.Port)
	suite.Equal("api-key", expAm.Type)
	suite.NotEqual("", expAm.UUID)
	suite.NotEqual("", expAm.CreatedOn)
}

// TestAuthMethodCreateAlreadyExists tests the case where there is an already existing auth method for the given service type and host
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodCreateAlreadyExists() {

	reqBody := `{
 "access_key": "key1",
 "host": "host1",
 "port": 9000
}`

	expRespJSON := `{
 "error": {
  "message": "Auth method object with host: host1 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateUnknownServiceType tests the case where the provided service type is unknown
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodCreateUnknownServiceType() {

	reqBody := `{
 "access_key": "key1",
 "host": "host1",
 "port": 9000
}`

	expRespJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/unknown/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateUnknownHost tests the case where the provided host isn't declared for the given service type
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodCreateUnknownHost() {

	reqBody := `{
 "access_key": "key1",
 "host": "unknown",
 "port": 9000
}`

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateInvalidJSON tests the case where the request body is malformed
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodCreateInvalidJSON() {

	reqBody := `{
 "access_key": "key1",
 "host": "host1",
 "port": 9000
` // missing closing bracket

	expRespJSON := `{
 "error": {
  "message": "Poorly formatted JSON. unexpected EOF",
  "code": 400,
  "status": "BAD REQUEST"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(400, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateEmptyAccessKey tests the case where the request body contains an empty data for field access_key
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodCreateEmptyAccessKey() {

	reqBody := `{
 "host": "host2",
 "port": 9000
}`

	expRespJSON := `{
 "error": {
  "message": "auth method object contains empty fields. empty value for field: access_key",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateEmptyHost tests the case where the request body contains an empty data for field host
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodCreateEmptyHost() {

	reqBody := `{
 "access_key": "key",
 "port": 9000
}`

	expRespJSON := `{
 "error": {
  "message": "auth method object contains empty fields. empty value for field: host",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodCreateEmptyHost tests the case where the request body contains an empty data for field port
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodCreateEmptyPort() {

	reqBody := `{
 "access_key": "key",
 "host": "host1,"
}`

	expRespJSON := `{
 "error": {
  "message": "auth method object contains empty fields. empty value for field: port",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/authm", WrapConfig(AuthMethodCreate, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodListOne tests the normal case of finding the auth method associated with the given service type and host
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodListOne() {

	expRespJSON := `{
 "service_uuid": "uuid1",
 "port": 9000,
 "host": "host1",
 "type": "api-key",
 "uuid": "am_uuid_1",
 "created_on": "",
 "access_key": "access_key"
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/host1/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodListOneUnknownServiceType tests the case where the provided service type is unknown
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodListOneUnknownServiceType() {

	expRespJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/unknown/hosts/host1/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodListOneUnknownHost tests the case where the provided host is not associated with the given service-type
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodListOneUnknownHost() {

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/unknown/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodListOneNotFound tests the case where there is no registered auth method under the given service-type and host
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodListOneNotFound() {

	expRespJSON := `{
 "error": {
  "message": "Auth method was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("GET", "http://localhost:8080/service-types/s1/hosts/host3/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodListOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodListAll tests the normal case and returns all auth methods in the service type
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodListAll() {

	expRespJSON := `{
 "auth_methods": [
  {
   "service_uuid": "uuid1",
   "port": 9000,
   "host": "host1",
   "type": "api-key",
   "uuid": "am_uuid_1",
   "created_on": "",
   "access_key": "access_key"
  },
  {
   "service_uuid": "uuid2",
   "port": 9000,
   "host": "host3",
   "type": "headers",
   "uuid": "am_uuid_2",
   "created_on": "",
   "headers": {
    "Accept": "application/json",
    "x-api-key": "key-1"
   }
  }
 ]
}`

	amb1 := authmethods.BasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	apiKeyAm := &authmethods.ApiKeyAuthMethod{AccessKey: "access_key"}
	apiKeyAm.BasicAuthMethod = amb1

	amb2 := authmethods.BasicAuthMethod{ServiceUUID: "uuid2", Host: "host3", Port: 9000, Type: "headers", UUID: "am_uuid_2", CreatedOn: ""}
	headersAm := &authmethods.HeadersAuthMethod{Headers: map[string]string{"x-api-key": "key-1", "Accept": "application/json"}}
	headersAm.BasicAuthMethod = amb2
	req, err := http.NewRequest("GET", "http://localhost:8080/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authm", WrapConfig(AuthMethodListAll, mockstore, cfg))
	router.ServeHTTP(w, req)

	expectedAMList := map[string]interface{}{}

	_ = json.Unmarshal([]byte(expRespJSON), &expectedAMList)

	amList := expectedAMList["auth_methods"]
	amListCasted := amList.([]interface{})
	suite.Equal(2, len(amListCasted))

	for _, am := range amListCasted {
		_am := am.(map[string]interface{})
		if _am["type"] == "api-key" {
			suite.Equal(apiKeyAm.UUID, _am["uuid"])
			suite.Equal(apiKeyAm.CreatedOn, _am["created_on"])
			suite.Equal(apiKeyAm.AccessKey, _am["access_key"])
			suite.Equal(apiKeyAm.ServiceUUID, _am["service_uuid"])
			suite.Equal(apiKeyAm.Host, _am["host"])
			suite.Equal(apiKeyAm.Type, _am["type"])
			suite.Equal(float64(apiKeyAm.Port), _am["port"])
		} else {
			suite.Equal(headersAm.UUID, _am["uuid"])
			suite.Equal(headersAm.CreatedOn, _am["created_on"])
			for k, v := range _am["headers"].(map[string]interface{}) {
				if k == "Accept" {
					suite.Equal("application/json", v)
				} else if k == "x-api-key" {
					suite.Equal("key-1", v)
				}
			}
			suite.Equal(headersAm.ServiceUUID, _am["service_uuid"])
			suite.Equal(headersAm.Host, _am["host"])
			suite.Equal(float64(headersAm.Port), _am["port"])
		}
	}

	suite.Equal(200, w.Code)
}

// TestAuthMethodListAllEmptyList tests the normal case where there are no auth methods in the service yet
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodListAllEmptyList() {

	expRespJSON := `{
 "auth_methods": []
}`
	req, err := http.NewRequest("GET", "http://localhost:8080/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	// empty the mockstore
	mockstore.AuthMethods = []stores.QAuthMethod{}

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/authm", WrapConfig(AuthMethodListAll, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodDeleteOne tests the normal case
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodDelete() {

	req, err := http.NewRequest("DELETE", "http://localhost:8080/service-types/s1/hosts/host1/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodDeleteOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(204, w.Code)
	suite.Equal("null", w.Body.String())
}

// TestAuthMethodDeleteOneUnknownServiceType tests the case where the provided service type is unknown
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodDeleteOneUnknownServiceType() {

	expRespJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("DELETE", "http://localhost:8080/service-types/unknown/hosts/host1/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodDeleteOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodDeleteOneUnknownHost tests the case where the provided host is not associated with the given service-type
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodDeleteOneUnknownHost() {

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("DELETE", "http://localhost:8080/service-types/s1/hosts/unknown/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodDeleteOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodDeleteNotFound tests the case where there is no registered auth method under the given service-type and host
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodDeleteNotFound() {

	expRespJSON := `{
 "error": {
  "message": "Auth method was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("DELETE", "http://localhost:8080/service-types/s1/hosts/host3/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodDeleteOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOne tests the default case of updating an auth method of type api-key and service type of ams
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOne() {

	reqBody := `{
 "access_key": "key1",
 "retrieval_field": "some_token",
 "port": 9000
}`

	expRespJSON := `{
 "service_uuid": "uuid1",
 "port": 9000,
 "host": "host1",
 "type": "api-key",
 "uuid": "am_uuid_1",
 "created_on": "",
 "updated_on": "{{UPDATED_ON}}",
 "access_key": "key1"
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/hosts/host1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)

	amU, _ := mockstore.QueryApiKeyAuthMethods(context.Background(), "uuid1", "host1")
	expRespJSON = strings.Replace(expRespJSON, "{{UPDATED_ON}}", amU[0].UpdatedOn, 1)
	// make sure the updated time is before now
	updatedTime, _ := time.Parse(utils.ZULU_FORM, amU[0].UpdatedOn)
	suite.True(updatedTime.Before(time.Now().UTC()))
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOneIllegalFields tests the default case of updating an auth method of type api-key and service type of ams with values to fields that aren't supposed to change
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOneIllegalFields() {

	reqBody := `{
 "created_on": "some_time",
 "uuid": "some_uuid",
 "type": "some_type"
}`

	expRespJSON := `{
 "service_uuid": "uuid1",
 "port": 9000,
 "host": "host1",
 "type": "api-key",
 "uuid": "am_uuid_1",
 "created_on": "",
 "updated_on": "{{UPDATED_ON}}",
 "access_key": "access_key"
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/hosts/host1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)

	amU, _ := mockstore.QueryApiKeyAuthMethods(context.Background(), "uuid1", "host1")
	expRespJSON = strings.Replace(expRespJSON, "{{UPDATED_ON}}", amU[0].UpdatedOn, 1)
	// make sure the updated time is before now
	updatedTime, _ := time.Parse(utils.ZULU_FORM, amU[0].UpdatedOn)
	suite.True(updatedTime.Before(time.Now().UTC()))
	suite.Equal(200, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOneInvalidJSON tests the default case of updating an auth method of type api-key and service type of ams while the host and service type already have a registered auth method
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOneAlreadyExists() {

	reqBody := `{
 "service_uuid": "uuid2",
 "host": "host3"
}`

	expRespJSON := `{
 "error": {
  "message": "Auth method object with host: host3 already exists",
  "code": 409,
  "status": "CONFLICT"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/hosts/host1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	amb1 := stores.QBasicAuthMethod{ServiceUUID: "uuid2", Host: "host3", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	am1 := &stores.QApiKeyAuthMethod{AccessKey: "access_key"}
	am1.QBasicAuthMethod = amb1
	mockstore.AuthMethods = append(mockstore.AuthMethods, am1)

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(409, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOneInvalidJSON tests the default case of updating an auth method of type api-key and service type of ams while providing an invalid request body
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOneInvalidJSON() {

	reqBody := `{
 "access_key": "key1",
 "retrieval_field": "some_token",
 "port": 9000
` // no closing bracket

	expRespJSON := `{
 "error": {
  "message": "Poorly formatted JSON. unexpected EOF",
  "code": 400,
  "status": "BAD REQUEST"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/hosts/host1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(400, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOneEmptyHost  tests the default case of updating an auth method of type api-key and service type of ams while providing an empty host
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOneEmptyHost() {

	reqBody := `{
 "host": ""
}`

	expRespJSON := `{
 "error": {
  "message": "auth method object contains empty fields. empty value for field: host",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/hosts/host1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOneEmptyServiceUUID tests the default case of updating an auth method of type api-key and service type of ams while providing an empty service uuid
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOneEmptyServiceUUID() {

	reqBody := `{
 "service_uuid": ""
}`

	expRespJSON := `{
 "error": {
  "message": "auth method object contains empty fields. empty value for field: service_uuid",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/hosts/host1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOneEmptyPort tests the default case of updating an auth method of type api-key and service type of ams while providing an empty port
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOneEmptyPort() {

	reqBody := `{
 "port": 0
}`

	expRespJSON := `{
 "error": {
  "message": "auth method object contains empty fields. empty value for field: port",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/hosts/host1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOneEmptyAccessKey tests the default case of updating an auth method of type api-key and service type of ams while providing an empty access key
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOneEmptyAccessKey() {

	reqBody := `{
"access_key": ""
}`

	expRespJSON := `{
 "error": {
  "message": "auth method object contains empty fields. empty value for field: access_key",
  "code": 422,
  "status": "UNPROCESSABLE ENTITY"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/hosts/host1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(422, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOneInvalidFieldType tests the default case of updating an auth method of type api-key and service type of ams while providing a wrong value for field regarding its type
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOneInvalidFieldType() {

	reqBody := `{
"port": "9000"
}`

	expRespJSON := `{
 "error": {
  "message": "Poorly formatted JSON. json: cannot unmarshal string into Go struct field TempApiKeyAuthMethod.port of type int",
  "code": 400,
  "status": "BAD REQUEST"
 }
}`

	req, err := http.NewRequest("POST", "http://localhost:8080/service-types/s1/hosts/host1/authm", bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(400, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOneUnknownServiceType tests the case where the provided service type is unknown
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOneUnknownServiceType() {

	expRespJSON := `{
 "error": {
  "message": "Service-type was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/unknown/hosts/host1/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodDUpdateOneUnknownHost tests the case where the provided host is not associated with the given service-type
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodDUpdateOneUnknownHost() {

	expRespJSON := `{
 "error": {
  "message": "Host was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/unknown/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

// TestAuthMethodUpdateOneNotFound tests the case where there is no registered auth method under the given service-type and host
func (suite *AuthMethodsHandlersTestSuite) TestAuthMethodUpdateOneNotFound() {

	expRespJSON := `{
 "error": {
  "message": "Auth method was not found",
  "code": 404,
  "status": "NOT FOUND"
 }
}`

	req, err := http.NewRequest("PUT", "http://localhost:8080/service-types/s1/hosts/host3/authm", nil)
	if err != nil {
		LOGGER.Error(err.Error())
	}

	mockstore := &stores.Mockstore{Server: "localhost", Database: "test_db"}
	mockstore.SetUp()

	cfg := &config.Config{}
	_ = cfg.ConfigSetUp("../config/configuration-test-files/test-conf.json")

	router := mux.NewRouter().StrictSlash(true)
	w := httptest.NewRecorder()
	router.HandleFunc("/service-types/{service-type}/hosts/{host}/authm", WrapConfig(AuthMethodUpdateOne, mockstore, cfg))
	router.ServeHTTP(w, req)
	suite.Equal(404, w.Code)
	suite.Equal(expRespJSON, w.Body.String())
}

func TestAuthMethodsHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(AuthMethodsHandlersTestSuite))
}
