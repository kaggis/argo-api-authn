package stores

import (
	"github.com/stretchr/testify/suite"
	"testing"
)

type StoreTestSuite struct {
	suite.Suite
	Mockstore Mockstore
}

// SetUpTestSuite assigns the mock store to be used in the querying tests
// It should be used on each test case so CRUD operations don't need to be reverted
func (suite *StoreTestSuite) SetUpStoreTestSuite() {

	mockstore := &Mockstore{}
	mockstore.Setup("localhost", "test_db")
	suite.Mockstore = *mockstore
}

// TestSetUp tests if the mockstore setup has been completed successfully
func (suite *StoreTestSuite) TestSetUp() {

	suite.SetUpStoreTestSuite()

	mockstore := &Mockstore{}
	mockstore.Setup("localhost", "test_db")

	var qServices []QService
	var qBindings []QBinding
	var authTypes []interface{}

	// Populate qServices
	service1 := QService{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509, oidc"}, AuthMethod: "api-key", RetrievalField: "token"}
	service2 := QService{Name: "s2", Hosts: []string{"host3", "host4"}, AuthTypes: []string{"x509"}, AuthMethod: "api-key", RetrievalField: "user_token"}
	qServices = append(qServices, service1, service2)

	// Populate Bindings
	binding1 := QBinding{Name: "b1", Service: "s1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding2 := QBinding{Name: "b2", Service: "s1", Host: "host1", DN: "test_dn_2", OIDCToken: "", UniqueKey: "unique_key_2", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding3 := QBinding{Name: "b3", Service: "s2", Host: "host2", DN: "test_dn_3", OIDCToken: "", UniqueKey: "unique_key_3", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}

	qBindings = append(qBindings, binding1, binding2, binding3)

	// Populate AuthTypes
	apiKeyAuth1 := QApiKeyAuth{Type: "api-key", Service: "s1", Host: "host1", Path: "test_path_1", Port: 9000, AccessKey: "key1"}
	authTypes = append(authTypes, apiKeyAuth1)

	suite.Equal(mockstore.Session, true)
	suite.Equal(mockstore.Database, "test_db")
	suite.Equal(mockstore.Server, "localhost")
	suite.Equal(mockstore.Services, qServices)
	suite.Equal(mockstore.Bindings, qBindings)
	suite.Equal(mockstore.AuthTypes, authTypes)
}

func (suite *StoreTestSuite) TestClose() {

	suite.SetUpStoreTestSuite()

	suite.Mockstore.Close()
	suite.Equal(false, suite.Mockstore.Session)
}

func (suite *StoreTestSuite) TestQueryServices() {

	suite.SetUpStoreTestSuite()

	// normal case outcome - 1 service
	expQServices1 := []QService{{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509, oidc"}, AuthMethod: "api-key", RetrievalField: "token"}}
	qServices1, err1 := suite.Mockstore.QueryServices("s1")
	expQServices2 := []QService{{Name: "s2", Hosts: []string{"host3", "host4"}, AuthTypes: []string{"x509"}, AuthMethod: "api-key", RetrievalField: "user_token"}}
	qServices2, err2 := suite.Mockstore.QueryServices("s2")

	// normal case outcome - all services
	expQServicesAll := []QService{
		{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509, oidc"}, AuthMethod: "api-key", RetrievalField: "token"},
		{Name: "s2", Hosts: []string{"host3", "host4"}, AuthTypes: []string{"x509"}, AuthMethod: "api-key", RetrievalField: "user_token"}}
	qServicesAll, errAll := suite.Mockstore.QueryServices("")

	// was not found
	var expQService3 []QService
	qServices3, err3 := suite.Mockstore.QueryServices("wrong_name")

	// tests the normal case - 1 service
	suite.Equal(expQServices1, qServices1)
	suite.Nil(err1)
	suite.Equal(expQServices2, qServices2)
	suite.Nil(err2)

	// tests the normal case - all services
	suite.Equal(expQServicesAll, qServicesAll)
	suite.Nil(errAll)

	// tests the not found case
	suite.Equal(expQService3, qServices3)
	suite.Nil(err3)
}

func (suite *StoreTestSuite) TestQueryAuthMethod() {

	suite.SetUpStoreTestSuite()

	// normal case outcome
	expAuthType1 := map[string]interface{}{"Type": "api-key", "Service": "s1", "Host": "host1", "Path": "test_path_1", "Port": 9000, "AccessKey": "key1"}
	authType1, err1 := suite.Mockstore.QueryAuthMethod("s1", "host1", "api-key")

	// was not found
	authType2, err2 := suite.Mockstore.QueryAuthMethod("wrong_service", "wrong_host", "wrong_type")

	// tests the normal case
	suite.Equal(expAuthType1, authType1)
	suite.Nil(err1)

	// tests the not found case
	suite.Equal(0, len(authType2))
	suite.Nil(err2)
}

func (suite *StoreTestSuite) TestQueryBindingsByDN() {

	suite.SetUpStoreTestSuite()

	// normal case
	expBinding1 := []QBinding{{Name: "b1", Service: "s1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}}
	qBinding1, err1 := suite.Mockstore.QueryBindingsByDN("test_dn_1", "host1")

	// not found case
	var expBinding2 []QBinding
	qBinding2, err2 := suite.Mockstore.QueryBindingsByDN("wrong_dn", "wrong_host")

	// tests the normal case
	suite.Equal(expBinding1, qBinding1)
	suite.Nil(err1)

	//tests the not found case
	suite.Equal(expBinding2, qBinding2)
	suite.Nil(err2)
}

func (suite *StoreTestSuite) TestQueryBindings() {

	suite.SetUpStoreTestSuite()

	// normal case - with parameters
	expBindings1 := []QBinding{
		{Name: "b1", Service: "s1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
		{Name: "b2", Service: "s1", Host: "host1", DN: "test_dn_2", OIDCToken: "", UniqueKey: "unique_key_2", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
	}
	qBindings1, err1 := suite.Mockstore.QueryBindings("s1", "host1")

	// normal case - without parameters
	expBindings2 := []QBinding{
		{Name: "b1", Service: "s1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
		{Name: "b2", Service: "s1", Host: "host1", DN: "test_dn_2", OIDCToken: "", UniqueKey: "unique_key_2", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
		{Name: "b3", Service: "s2", Host: "host2", DN: "test_dn_3", OIDCToken: "", UniqueKey: "unique_key_3", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""},
	}
	qBindings2, err2 := suite.Mockstore.QueryBindings("", "")

	// ot result case - with parameters
	var expBindings3 []QBinding
	qBindings3, err3 := suite.Mockstore.QueryBindings("wrong_service", "wrong_host")

	// tests the normal case - with parameters
	suite.Equal(expBindings1, qBindings1)
	suite.Nil(err1)

	// tests the normal case - without parameters
	suite.Equal(expBindings2, qBindings2)
	suite.Nil(err2)

	// tests the no result case - with parameters
	suite.Equal(expBindings3, qBindings3)
	suite.Nil(err3)
}

func (suite *StoreTestSuite) TestInsertBinding() {

	suite.SetUpStoreTestSuite()

	var expBinding1 QBinding

	_, err1 := suite.Mockstore.InsertBinding("bIns", "s1", "host1", "test_dn_ins", "", "unique_key_ins")

	// check if the new binding can be found
	expBindings, _ := suite.Mockstore.QueryBindingsByDN("test_dn_ins", "host1")
	expBinding1 = expBindings[0]

	suite.Equal("bIns", expBinding1.Name)
	suite.Equal("s1", expBinding1.Service)
	suite.Equal("host1", expBinding1.Host)
	suite.Equal("test_dn_ins", expBinding1.DN)
	suite.Equal("", expBinding1.OIDCToken)
	suite.Equal("unique_key_ins", expBinding1.UniqueKey)
	suite.Nil(err1)
}

func (suite *StoreTestSuite) TestUpdateBinding() {

	suite.SetUpStoreTestSuite()

	original := QBinding{Name: "b1", Service: "s1", Host: "host1", DN: "test_dn_1", OIDCToken: "", UniqueKey: "unique_key_1", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	updated := QBinding{Name: "b1", Service: "s1", Host: "host1", DN: "test_dn_upd", OIDCToken: "", UniqueKey: "unique_key_upd", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}

	_, err1 := suite.Mockstore.UpdateBinding(original, updated)

	expBindings, _ := suite.Mockstore.QueryBindingsByDN("test_dn_upd", "host1")
	expBinding1 := expBindings[0]

	suite.Equal(expBinding1, updated)
	suite.Nil(err1)
}

func TestStoreTestSuite(t *testing.T) {
	suite.Run(t, new(StoreTestSuite))
}
