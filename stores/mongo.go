package stores

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ARGOeu/argo-api-authn/utils"
	log "github.com/sirupsen/logrus"
	officialBson "go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type MongoStore struct {
	Server   string
	Database string
	Session  *mgo.Session
}

// SetUp initializes the mongo stores struct
func (mongo *MongoStore) SetUp() {

	for {
		log.WithFields(
			log.Fields{
				"type":            "backend_log",
				"backend_service": "mongo",
				"backend_hosts":   mongo.Server,
			},
		).Info("Trying to connect to Mongo")
		session, err := mgo.Dial(mongo.Server)
		if err != nil {
			log.WithFields(
				log.Fields{
					"type":            "backend_log",
					"backend_service": "mongo",
					"backend_hosts":   mongo.Server,
				},
			).Error(err.Error())
			continue
		}

		mongo.Session = session
		log.WithFields(
			log.Fields{
				"type":            "backend_log",
				"backend_service": "mongo",
				"backend_hosts":   mongo.Server,
			},
		).Info("Connection to Mongo established successfully")
		break
	}
}

func (mongo *MongoStore) Clone() Store {

	return &MongoStore{
		Server:   mongo.Server,
		Database: mongo.Database,
		Session:  mongo.Session.Clone(),
	}
}

func (mongo *MongoStore) Close() {
	mongo.Session.Close()
}

func (mongo *MongoStore) logError(ctx context.Context, funcName string, err error) {
	log.WithFields(
		log.Fields{
			"trace_id":        ctx.Value("trace_id"),
			"type":            "backend_log",
			"function":        funcName,
			"backend_service": "mongo",
			"backend_hosts":   mongo.Server,
		},
	).Error(err.Error())
}

func (mongo *MongoStore) InsertBindingMissingIpSanRecord(ctx context.Context, bindingUUID, bindingAuthId, createdOn string) error {

	qMetric := QMissingIpSanMetric{
		BindingUUID:           bindingUUID,
		BindingAuthIdentifier: bindingAuthId,
		CreatedOn:             createdOn,
	}

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings_missing_ip_san")

	if err := c.Insert(qMetric); err != nil {
		mongo.logError(ctx, "InsertBindingMissingIpSanRecord", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return nil
}

func (mongo *MongoStore) QueryBindingMissingIpSanRecord(ctx context.Context, bindingUUID string) ([]QMissingIpSanMetric, error) {

	var qMetrics []QMissingIpSanMetric
	var err error

	c := mongo.Session.DB(mongo.Database).C("bindings_missing_ip_san")
	query := bson.M{}

	if bindingUUID != "" {
		query = bson.M{"name": bindingUUID}
	}

	err = c.Find(query).All(&qMetrics)

	if err != nil {
		mongo.logError(ctx, "QueryBindingMissingIpSanRecord", err)
		err = utils.APIErrDatabase(err.Error())
		return []QMissingIpSanMetric{}, err
	}

	return qMetrics, err
}

func (mongo *MongoStore) QueryServiceTypes(ctx context.Context, name string) ([]QServiceType, error) {

	var qServices []QServiceType
	var err error

	c := mongo.Session.DB(mongo.Database).C("service_types")
	query := bson.M{}

	if name != "" {
		query = bson.M{"name": name}
	}

	err = c.Find(query).All(&qServices)

	if err != nil {
		mongo.logError(ctx, "QueryServiceTypes", err)
		err = utils.APIErrDatabase(err.Error())
		return []QServiceType{}, err
	}

	return qServices, err
}

func (mongo *MongoStore) QueryServiceTypesByUUID(ctx context.Context, uuid string) ([]QServiceType, error) {

	var qServices []QServiceType
	var err error

	c := mongo.Session.DB(mongo.Database).C("service_types")

	err = c.Find(bson.M{"uuid": uuid}).All(&qServices)

	if err != nil {
		mongo.logError(ctx, "QueryServiceTypesByUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return []QServiceType{}, err
	}

	return qServices, err
}

func (mongo *MongoStore) QueryApiKeyAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QApiKeyAuthMethod, error) {

	var err error
	var qAuthms []QApiKeyAuthMethod

	var query = bson.M{"service_uuid": serviceUUID, "host": host, "type": "api-key"}

	// if there is no serviceUUID and host provided, return all api key auth methods
	if serviceUUID == "" && host == "" {
		query = bson.M{"type": "api-key"}
	}

	c := mongo.Session.DB(mongo.Database).C("auth_methods")
	err = c.Find(query).All(&qAuthms)

	if err != nil {
		mongo.logError(ctx, "QueryApiKeyAuthMethods", err)
		err = utils.APIErrDatabase(err.Error())
		return qAuthms, err
	}

	return qAuthms, err
}

func (mongo *MongoStore) QueryHeadersAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QHeadersAuthMethod, error) {

	var err error
	var qAuthms []QHeadersAuthMethod

	var query = bson.M{"service_uuid": serviceUUID, "host": host, "type": "headers"}

	// if there is no serviceUUID and host provided, return all api key auth methods
	if serviceUUID == "" && host == "" {
		query = bson.M{"type": "headers"}
	}

	c := mongo.Session.DB(mongo.Database).C("auth_methods")
	err = c.Find(query).All(&qAuthms)

	if err != nil {
		mongo.logError(ctx, "QueryHeadersAuthMethods", err)
		err = utils.APIErrDatabase(err.Error())
		return qAuthms, err
	}

	return qAuthms, err
}

func (mongo *MongoStore) InsertAuthMethod(ctx context.Context, am QAuthMethod) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("auth_methods")

	if err := c.Insert(am); err != nil {
		mongo.logError(ctx, "InsertAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return err
}

func (mongo *MongoStore) QueryBindingsByAuthID(ctx context.Context, authID string, serviceUUID string, host string, authType string) ([]QBinding, error) {

	var qBindings []QBinding
	var err error

	c := mongo.Session.DB(mongo.Database).C("bindings")

	query := bson.M{
		"auth_identifier": authID,
		"service_uuid":    serviceUUID,
		"host":            host,
		"auth_type":       authType,
	}

	err = c.Find(query).All(&qBindings)

	if err != nil {
		mongo.logError(ctx, "QueryBindingsByAuthID", err)
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, err
}

func (mongo *MongoStore) QueryBindingsByUUIDAndName(ctx context.Context, uuid, name string) ([]QBinding, error) {

	var qBindings []QBinding
	var err error

	q := bson.M{}

	if uuid != "" {
		q["uuid"] = uuid
	}

	if name != "" {
		q["name"] = name
	}

	c := mongo.Session.DB(mongo.Database).C("bindings")
	err = c.Find(q).All(&qBindings)

	if err != nil {
		mongo.logError(ctx, "QueryBindingsByUUIDAndName", err)
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, err
}

func (mongo *MongoStore) QueryBindings(ctx context.Context, serviceUUID string, host string) ([]QBinding, error) {

	var qBindings []QBinding
	var err error
	query := bson.M{}

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if serviceUUID != "" && host != "" {
		query = bson.M{"service_uuid": serviceUUID, "host": host}
	}

	if err = c.Find(query).All(&qBindings); err != nil {
		mongo.logError(ctx, "QueryBindings", err)
		err = utils.APIErrDatabase(err.Error())
		return qBindings, err
	}
	return qBindings, err
}

// InsertServiceType inserts a new service into the datastore
func (mongo *MongoStore) InsertServiceType(ctx context.Context, name string, hosts []string, authTypes []string, authMethod string, uuid string, createdOn string, sType string) (QServiceType, error) {

	var qService QServiceType
	var err error

	qService = QServiceType{Name: name, Hosts: hosts, AuthTypes: authTypes, AuthMethod: authMethod, UUID: uuid, CreatedOn: createdOn, Type: sType}
	db := mongo.Session.DB(mongo.Database)
	c := db.C("service_types")

	if err := c.Insert(qService); err != nil {
		mongo.logError(ctx, "InsertServiceType", err)
		err = utils.APIErrDatabase(err.Error())
		return QServiceType{}, err
	}

	return qService, err
}

// InsertBinding inserts a new binding into the datastore
func (mongo *MongoStore) InsertBinding(ctx context.Context, name string, serviceUUID string, host string, uuid string, authID string, uniqueKey string, authType string) (QBinding, error) {

	var qBinding QBinding
	var err error

	qBinding = QBinding{
		Name:           name,
		ServiceUUID:    serviceUUID,
		Host:           host,
		UUID:           uuid,
		AuthIdentifier: authID,
		UniqueKey:      uniqueKey,
		AuthType:       authType,
		CreatedOn:      utils.ZuluTimeNow(),
	}

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if err := c.Insert(qBinding); err != nil {
		mongo.logError(ctx, "InsertBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return QBinding{}, err
	}

	return qBinding, err
}

// UpdateBinding updates the given binding
func (mongo *MongoStore) UpdateBinding(ctx context.Context, original QBinding, updated QBinding) (QBinding, error) {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if err := c.Update(original, updated); err != nil {
		mongo.logError(ctx, "UpdateBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return QBinding{}, err
	}

	return updated, err
}

// UpdateServiceType updates the given binding
func (mongo *MongoStore) UpdateServiceType(ctx context.Context, original QServiceType, updated QServiceType) (QServiceType, error) {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("service_types")

	if err := c.Update(original, updated); err != nil {
		mongo.logError(ctx, "UpdateServiceType", err)
		err = utils.APIErrDatabase(err.Error())
		return QServiceType{}, err
	}

	return updated, err
}

// UpdateAuthMethod updates the given auth method
func (mongo *MongoStore) UpdateAuthMethod(ctx context.Context, original QAuthMethod, updated QAuthMethod) (QAuthMethod, error) {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("auth_methods")
	if err := c.Update(original, updated); err != nil {
		mongo.logError(ctx, "UpdateAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return nil, err
	}

	return updated, err
}

func (mongo *MongoStore) DeleteServiceTypeByUUID(ctx context.Context, uuid string) error {

	var err error

	c := mongo.Session.DB(mongo.Database).C("service_types")

	err = c.Remove(bson.M{"uuid": uuid})

	if err != nil {
		mongo.logError(ctx, "DeleteServiceTypeByUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return err
}

// DeleteBinding deletes a binding from the store
func (mongo *MongoStore) DeleteBinding(ctx context.Context, qBinding QBinding) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if err := c.Remove(qBinding); err != nil {
		mongo.logError(ctx, "DeleteBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return err
}

func (mongo *MongoStore) DeleteBindingByServiceUUID(ctx context.Context, serviceUUID string) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("bindings")

	if _, err = c.RemoveAll(bson.M{"service_uuid": serviceUUID}); err != nil {
		mongo.logError(ctx, "DeleteBindingByServiceUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return err
}

func (mongo *MongoStore) DeleteAuthMethod(ctx context.Context, am QAuthMethod) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("auth_methods")

	if err := c.Remove(am); err != nil {
		mongo.logError(ctx, "DeleteAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return err
}

func (mongo *MongoStore) DeleteAuthMethodByServiceUUID(ctx context.Context, serviceUUID string) error {

	var err error

	db := mongo.Session.DB(mongo.Database)
	c := db.C("auth_methods")

	if _, err = c.RemoveAll(bson.M{"service_uuid": serviceUUID}); err != nil {
		mongo.logError(ctx, "DeleteAuthMethodByServiceUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return err

}

type MongoStoreWithOfficialDriver struct {
	Server   string
	Database string
	database *mongo.Database
	client   *mongo.Client
}

func (store *MongoStoreWithOfficialDriver) logError(ctx context.Context, funcName string, err error) {
	log.WithFields(
		log.Fields{
			"trace_id":        ctx.Value("trace_id"),
			"type":            "backend_log",
			"function":        funcName,
			"backend_service": "mongo",
			"backend_hosts":   store.Server,
		},
	).Error(err.Error())
}

func (store *MongoStoreWithOfficialDriver) SetUp() {

	mongoDBUri := fmt.Sprintf("mongodb://%s", store.Server)

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		log.WithFields(
			log.Fields{
				"type":            "backend_log",
				"backend_service": "mongo",
				"backend_hosts":   store.Server,
			},
		).Info("Trying to connect to Mongo")
		client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoDBUri))
		if err != nil {
			log.WithFields(
				log.Fields{
					"type":            "backend_log",
					"backend_service": "mongo",
					"backend_hosts":   store.Server,
				},
			).Error(err.Error())
			continue
		}
		store.client = client
		cancel()
		break
	}

	log.WithFields(
		log.Fields{
			"type":            "backend_log",
			"backend_service": "mongo",
			"backend_hosts":   store.Server,
		},
	).Info("Connection to Mongo established successfully")

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		log.WithFields(
			log.Fields{
				"type":            "backend_log",
				"backend_service": "mongo",
				"backend_hosts":   store.Server,
			},
		).Info("Trying to ping to Mongo")
		err := store.client.Ping(ctx, readpref.Primary())
		if err != nil {
			log.WithFields(
				log.Fields{
					"type":            "backend_log",
					"backend_service": "mongo",
					"backend_hosts":   store.Server,
				},
			).Error(err.Error())
			continue
		}
		cancel()
		break
	}

	log.WithFields(
		log.Fields{
			"type":            "backend_log",
			"backend_service": "mongo",
			"backend_hosts":   store.Server,
		},
	).Info("Mongo Deployment is up and running")
	store.database = store.client.Database(store.Database)
}

func (store *MongoStoreWithOfficialDriver) Close() {
	if store.client != nil {
		if err := store.client.Disconnect(context.Background()); err != nil {
			log.Fatalf("Could not disconnect mongo client, %s", err.Error())
		}
	}
}

func (store *MongoStoreWithOfficialDriver) Clone() Store {
	return store
}

func (store *MongoStoreWithOfficialDriver) InsertBindingMissingIpSanRecord(ctx context.Context, bindingUUID, bindingAuthId, createdOn string) error {

	qMetric := QMissingIpSanMetric{
		BindingUUID:           bindingUUID,
		BindingAuthIdentifier: bindingAuthId,
		CreatedOn:             createdOn,
	}

	_, err := store.database.Collection("bindings_missing_ip_san").InsertOne(ctx, qMetric)
	if err != nil {
		store.logError(ctx, "InsertBindingMissingIpSanRecord", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return nil
}

func (store *MongoStoreWithOfficialDriver) QueryBindingMissingIpSanRecord(ctx context.Context,
	bindingUUID string) ([]QMissingIpSanMetric, error) {

	var qMetrics []QMissingIpSanMetric
	query := officialBson.M{}

	if bindingUUID != "" {
		query["binding_uuid"] = bindingUUID
	}
	cursor, err := store.database.Collection("bindings_missing_ip_san").Find(ctx, query)
	if err != nil {
		return qMetrics, err
	}

	for cursor.Next(ctx) {
		var result QMissingIpSanMetric
		err := cursor.Decode(&result)
		if err != nil {
			store.logError(ctx, "QueryBindingMissingIpSanRecord", err)
			err = utils.APIErrDatabase(err.Error())
			return qMetrics, err
		}
		qMetrics = append(qMetrics, result)
	}

	if err := cursor.Err(); err != nil {
		store.logError(ctx, "QueryBindingMissingIpSanRecord", err)
		err = utils.APIErrDatabase(err.Error())
		return qMetrics, err
	}

	return qMetrics, nil
}

// ##### CRUD SERVICE TYPES #####

func (store *MongoStoreWithOfficialDriver) executeServiceTypesRetrieveQuery(ctx context.Context, query officialBson.M) ([]QServiceType, error) {

	var qServices []QServiceType
	c := store.database.Collection("service_types")

	cursor, err := c.Find(ctx, query)
	if err != nil {
		return qServices, err
	}

	for cursor.Next(ctx) {
		var result QServiceType
		err := cursor.Decode(&result)
		if err != nil {
			return qServices, err
		}
		qServices = append(qServices, result)
	}

	if err := cursor.Err(); err != nil {
		return qServices, err
	}

	return qServices, nil
}

func (store *MongoStoreWithOfficialDriver) QueryServiceTypes(ctx context.Context, name string) ([]QServiceType, error) {

	query := officialBson.M{}

	if name != "" {
		query["name"] = name
	}

	qServices, err := store.executeServiceTypesRetrieveQuery(ctx, query)
	if err != nil {
		store.logError(ctx, "QueryServiceTypes", err)
		err = utils.APIErrDatabase(err.Error())
		return []QServiceType{}, err
	}

	return qServices, nil
}

func (store *MongoStoreWithOfficialDriver) QueryServiceTypesByUUID(ctx context.Context, uuid string) ([]QServiceType, error) {
	query := officialBson.M{"uuid": uuid}

	qServices, err := store.executeServiceTypesRetrieveQuery(ctx, query)
	if err != nil {
		store.logError(ctx, "QueryServiceTypesByUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return []QServiceType{}, err
	}

	return qServices, nil
}

func (store *MongoStoreWithOfficialDriver) InsertServiceType(ctx context.Context, name string, hosts []string,
	authTypes []string, authMethod string, uuid string, createdOn string, sType string) (QServiceType, error) {

	qService := QServiceType{
		Name:       name,
		Hosts:      hosts,
		AuthTypes:  authTypes,
		AuthMethod: authMethod,
		UUID:       uuid,
		CreatedOn:  createdOn,
		Type:       sType,
	}

	_, err := store.database.Collection("service_types").InsertOne(ctx, qService)
	if err != nil {
		store.logError(ctx, "InsertServiceType", err)
		err = utils.APIErrDatabase(err.Error())
		return QServiceType{}, err
	}

	return qService, nil
}

func (store *MongoStoreWithOfficialDriver) DeleteServiceTypeByUUID(ctx context.Context, uuid string) error {
	query := officialBson.M{"uuid": uuid}
	_, err := store.database.Collection("service_types").DeleteOne(ctx, query)
	if err != nil {
		store.logError(ctx, "DeleteServiceTypeByUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return nil
}

func (store *MongoStoreWithOfficialDriver) UpdateServiceType(ctx context.Context,
	original QServiceType, updated QServiceType) (QServiceType, error) {

	query := officialBson.D{{"uuid", original.UUID}}
	updateQuery := officialBson.D{
		{"$set", officialBson.D{
			{"name", updated.Name},
			{"hosts", updated.Hosts},
			{"auth_types", updated.AuthTypes},
			{"auth_method", updated.AuthMethod},
			{"created_on", updated.CreatedOn},
			{"updated_on", updated.UpdatedOn},
			{"type", updated.Type},
		}}}
	_, err := store.database.Collection("service_types").UpdateOne(ctx, query, updateQuery)
	if err != nil {
		store.logError(ctx, "UpdateServiceType", err)
		err = utils.APIErrDatabase(err.Error())
		return QServiceType{}, err
	}
	return updated, nil
}

//	###### CRUD AUTH METHODS ######

func (store *MongoStoreWithOfficialDriver) QueryApiKeyAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QApiKeyAuthMethod, error) {

	var qAms []QApiKeyAuthMethod
	c := store.database.Collection("auth_methods")

	// if there is no serviceUUID and host provided, return all api key auth methods
	query := officialBson.M{"type": "api-key"}
	if serviceUUID != "" && host != "" {
		query["service_uuid"] = serviceUUID
		query["host"] = host
	}
	cursor, err := c.Find(ctx, query)
	if err != nil {
		store.logError(ctx, "QueryApiKeyAuthMethods", err)
		err = utils.APIErrDatabase(err.Error())
		return qAms, err
	}

	for cursor.Next(ctx) {
		var result QApiKeyAuthMethod
		err := cursor.Decode(&result)
		if err != nil {
			store.logError(ctx, "QueryApiKeyAuthMethods", err)
			err = utils.APIErrDatabase(err.Error())
			return qAms, err
		}
		qAms = append(qAms, result)
	}

	if err := cursor.Err(); err != nil {
		store.logError(ctx, "QueryApiKeyAuthMethods", err)
		err = utils.APIErrDatabase(err.Error())
		return qAms, err
	}

	return qAms, nil
}

func (store *MongoStoreWithOfficialDriver) QueryHeadersAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QHeadersAuthMethod, error) {

	var qAms []QHeadersAuthMethod
	c := store.database.Collection("auth_methods")

	// if there is no serviceUUID and host provided, return all api key auth methods
	query := officialBson.M{"type": "headers"}
	if serviceUUID != "" && host != "" {
		query["service_uuid"] = serviceUUID
		query["host"] = host
	}
	cursor, err := c.Find(ctx, query)
	if err != nil {
		store.logError(ctx, "QueryHeadersAuthMethods", err)
		err = utils.APIErrDatabase(err.Error())
		return qAms, err
	}

	for cursor.Next(ctx) {
		var result QHeadersAuthMethod
		err := cursor.Decode(&result)
		if err != nil {
			store.logError(ctx, "QueryHeadersAuthMethods", err)
			err = utils.APIErrDatabase(err.Error())
			return qAms, err
		}
		qAms = append(qAms, result)
	}

	if err := cursor.Err(); err != nil {
		store.logError(ctx, "QueryHeadersAuthMethods", err)
		err = utils.APIErrDatabase(err.Error())
		return qAms, err
	}

	return qAms, nil
}

func (store *MongoStoreWithOfficialDriver) InsertAuthMethod(ctx context.Context, am QAuthMethod) error {
	_, err := store.database.Collection("auth_methods").InsertOne(ctx, am)
	if err != nil {
		store.logError(ctx, "InsertAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}

	return nil
}

func (store *MongoStoreWithOfficialDriver) UpdateAuthMethod(ctx context.Context, original QAuthMethod, updated QAuthMethod) (QAuthMethod, error) {

	var query officialBson.D
	var updateQuery officialBson.D

	if apiKeyAM, ok := updated.(QApiKeyAuthMethod); ok {

		query = officialBson.D{{"uuid", apiKeyAM.UUID}}
		updateQuery = officialBson.D{{"$set", officialBson.D{
			{"access_key", apiKeyAM.AccessKey},
			{"service_uuid", apiKeyAM.ServiceUUID},
			{"host", apiKeyAM.Host},
			{"port", apiKeyAM.Port},
			{"created_on", apiKeyAM.CreatedOn},
			{"updated_on", apiKeyAM.UpdatedOn},
			{"type", apiKeyAM.Type},
		}}}
	} else if headersAm, ok := updated.(QHeadersAuthMethod); ok {
		query = officialBson.D{{"uuid", headersAm.UUID}}
		updateQuery = officialBson.D{{"$set", officialBson.D{
			{"headers", headersAm.Headers},
			{"service_uuid", headersAm.ServiceUUID},
			{"host", headersAm.Host},
			{"port", headersAm.Port},
			{"created_on", headersAm.CreatedOn},
			{"updated_on", headersAm.UpdatedOn},
			{"type", headersAm.Type},
		}}}
	} else {
		err := errors.New("unknown Auth method type")
		store.logError(ctx, "UpdateAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return original, err
	}

	_, err := store.database.Collection("auth_methods").UpdateOne(ctx, query, updateQuery)
	if err != nil {
		store.logError(ctx, "UpdateAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return original, err
	}
	return updated, nil

}

func (store *MongoStoreWithOfficialDriver) DeleteAuthMethod(ctx context.Context, am QAuthMethod) error {
	query := officialBson.M{"uuid": am.Uuid()}
	_, err := store.database.Collection("auth_methods").DeleteOne(ctx, query)
	if err != nil {
		store.logError(ctx, "DeleteAuthMethod", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return nil
}

func (store *MongoStoreWithOfficialDriver) DeleteAuthMethodByServiceUUID(ctx context.Context, serviceUUID string) error {
	query := officialBson.M{"service_uuid": serviceUUID}
	_, err := store.database.Collection("auth_methods").DeleteOne(ctx, query)
	if err != nil {
		store.logError(ctx, "DeleteAuthMethodByServiceUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return nil
}

//	###### CRUD BINDINGS ######

func (store *MongoStoreWithOfficialDriver) executeBindingsRetrieveQuery(ctx context.Context, query officialBson.M) ([]QBinding, error) {

	var qBindings []QBinding
	c := store.database.Collection("bindings")

	cursor, err := c.Find(ctx, query)
	if err != nil {
		return qBindings, err
	}

	for cursor.Next(ctx) {
		var result QBinding
		err := cursor.Decode(&result)
		if err != nil {
			return qBindings, err
		}
		qBindings = append(qBindings, result)
	}

	if err := cursor.Err(); err != nil {
		return qBindings, err
	}

	return qBindings, nil
}

func (store *MongoStoreWithOfficialDriver) QueryBindingsByAuthID(ctx context.Context, authID string,
	serviceUUID string, host string, authType string) ([]QBinding, error) {
	query := officialBson.M{
		"auth_identifier": authID,
		"service_uuid":    serviceUUID,
		"host":            host,
		"auth_type":       authType,
	}

	qBindings, err := store.executeBindingsRetrieveQuery(ctx, query)

	if err != nil {
		store.logError(ctx, "QueryBindingsByAuthID", err)
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, nil
}

func (store *MongoStoreWithOfficialDriver) QueryBindingsByUUIDAndName(ctx context.Context, uuid, name string) ([]QBinding, error) {
	query := officialBson.M{}

	if uuid != "" {
		query["uuid"] = uuid
	}

	if name != "" {
		query["name"] = name
	}

	qBindings, err := store.executeBindingsRetrieveQuery(ctx, query)

	if err != nil {
		store.logError(ctx, "QueryBindingsByUUIDAndName", err)
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, nil
}

func (store *MongoStoreWithOfficialDriver) QueryBindings(ctx context.Context, serviceUUID string, host string) ([]QBinding, error) {
	query := officialBson.M{}

	if serviceUUID != "" && host != "" {
		query["service_uuid"] = serviceUUID
		query["host"] = host
	}

	qBindings, err := store.executeBindingsRetrieveQuery(ctx, query)

	if err != nil {
		store.logError(ctx, "QueryBindings", err)
		err = utils.APIErrDatabase(err.Error())
		return []QBinding{}, err
	}

	return qBindings, nil
}

func (store *MongoStoreWithOfficialDriver) InsertBinding(ctx context.Context, name string, serviceUUID string,
	host string, uuid string, authID string, uniqueKey string, authType string) (QBinding, error) {

	qBinding := QBinding{
		Name:           name,
		ServiceUUID:    serviceUUID,
		Host:           host,
		UUID:           uuid,
		AuthIdentifier: authID,
		UniqueKey:      uniqueKey,
		AuthType:       authType,
		CreatedOn:      utils.ZuluTimeNow(),
	}

	_, err := store.database.Collection("bindings").InsertOne(ctx, qBinding)
	if err != nil {
		store.logError(ctx, "InsertBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return QBinding{}, err
	}

	return qBinding, nil
}

func (store *MongoStoreWithOfficialDriver) UpdateBinding(ctx context.Context, original QBinding, updated QBinding) (QBinding, error) {
	query := officialBson.D{{"uuid", original.UUID}}
	updateQuery := officialBson.D{
		{"$set", officialBson.D{
			{"name", updated.Name},
			{"service_uuid", updated.ServiceUUID},
			{"host", updated.Host},
			{"auth_identifier", updated.AuthIdentifier},
			{"auth_type", updated.AuthType},
			{"unique_key", updated.UniqueKey},
			{"created_on", updated.CreatedOn},
			{"updated_on", updated.UpdatedOn},
			{"last_auth", updated.LastAuth},
		}}}
	_, err := store.database.Collection("bindings").UpdateOne(ctx, query, updateQuery)
	if err != nil {
		store.logError(ctx, "UpdateBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return QBinding{}, err
	}
	return updated, nil
}

func (store *MongoStoreWithOfficialDriver) DeleteBinding(ctx context.Context, qBinding QBinding) error {
	query := officialBson.M{"uuid": qBinding.UUID}
	_, err := store.database.Collection("bindings").DeleteOne(ctx, query)
	if err != nil {
		store.logError(ctx, "DeleteBinding", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return nil
}

func (store *MongoStoreWithOfficialDriver) DeleteBindingByServiceUUID(ctx context.Context, serviceUUID string) error {
	query := officialBson.M{"service_uuid": serviceUUID}
	_, err := store.database.Collection("bindings").DeleteOne(ctx, query)
	if err != nil {
		store.logError(ctx, "DeleteBindingByServiceUUID", err)
		err = utils.APIErrDatabase(err.Error())
		return err
	}
	return nil
}
