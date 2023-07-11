package stores

import (
	"context"
	"reflect"

	"github.com/ARGOeu/argo-api-authn/utils"
)

type Mockstore struct {
	Session             bool
	Server              string
	Database            string
	ServiceTypes        []QServiceType
	Bindings            []QBinding
	AuthMethods         []QAuthMethod
	MissingIpSanRecords []QMissingIpSanMetric
}

// SetUp is used to initialize the mock store
func (mock *Mockstore) SetUp() {

	mock.Session = true

	// Populate services
	service1 := QServiceType{Name: "s1", Hosts: []string{"host1", "host2", "host3"}, AuthTypes: []string{"x509", "oidc"}, AuthMethod: "api-key", UUID: "uuid1", CreatedOn: "2018-05-05T18:04:05Z", Type: "ams"}
	service2 := QServiceType{Name: "s2", Hosts: []string{"host3", "host4"}, AuthTypes: []string{"x509"}, AuthMethod: "headers", UUID: "uuid2", CreatedOn: "2018-05-05T18:04:05Z", Type: "web-api"}
	serviceSame1 := QServiceType{Name: "same_name"}
	serviceSame2 := QServiceType{Name: "same_name"}
	mock.ServiceTypes = append(mock.ServiceTypes, service1, service2, serviceSame1, serviceSame2)

	// Populate Bindings
	binding1 := QBinding{Name: "b1", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid1", AuthIdentifier: "test_dn_1", UniqueKey: "unique_key_1", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding2 := QBinding{Name: "b2", ServiceUUID: "uuid1", Host: "host1", UUID: "b_uuid2", AuthIdentifier: "test_dn_2", UniqueKey: "unique_key_2", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding3 := QBinding{Name: "b3", ServiceUUID: "uuid1", Host: "host2", UUID: "b_uuid3", AuthIdentifier: "test_dn_3", UniqueKey: "unique_key_3", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	binding4 := QBinding{Name: "b4", ServiceUUID: "uuid2", Host: "host3", UUID: "b_uuid4", AuthIdentifier: "test_dn_1", UniqueKey: "unique_key_1", AuthType: "x509", CreatedOn: "2018-05-05T15:04:05Z", LastAuth: ""}
	mock.Bindings = append(mock.Bindings, binding1, binding2, binding3, binding4)

	// Populate AuthMethods
	amb1 := QBasicAuthMethod{ServiceUUID: "uuid1", Host: "host1", Port: 9000, Type: "api-key", UUID: "am_uuid_1", CreatedOn: ""}
	am1 := &QApiKeyAuthMethod{AccessKey: "access_key"}
	am1.QBasicAuthMethod = amb1

	amb2 := QBasicAuthMethod{ServiceUUID: "uuid2", Host: "host3", Port: 9000, Type: "headers", UUID: "am_uuid_2", CreatedOn: ""}
	am2 := &QHeadersAuthMethod{Headers: map[string]string{"x-api-key": "key-1", "Accept": "application/json"}}
	am2.QBasicAuthMethod = amb2

	mock.AuthMethods = append(mock.AuthMethods, am1, am2)

	// Populate missing ip san records
	r1 := QMissingIpSanMetric{
		BindingUUID:           "b_uuid1",
		BindingAuthIdentifier: "b_dn_1",
		CreatedOn:             "now",
	}
	mock.MissingIpSanRecords = append(mock.MissingIpSanRecords, r1)
}

func (mock *Mockstore) Close() {
	mock.Session = false
}

func (mock *Mockstore) Clone() Store {

	return &Mockstore{
		Session:             mock.Session,
		Server:              mock.Server,
		Database:            mock.Database,
		ServiceTypes:        mock.ServiceTypes,
		Bindings:            mock.Bindings,
		AuthMethods:         mock.AuthMethods,
		MissingIpSanRecords: mock.MissingIpSanRecords,
	}
}

func (mock *Mockstore) InsertBindingMissingIpSanRecord(ctx context.Context, bindingUUID, bindingAuthId, createdOn string) error {
	r1 := QMissingIpSanMetric{
		BindingUUID:           bindingUUID,
		BindingAuthIdentifier: bindingAuthId,
		CreatedOn:             createdOn,
	}
	mock.MissingIpSanRecords = append(mock.MissingIpSanRecords, r1)
	return nil
}

func (mock *Mockstore) QueryBindingMissingIpSanRecord(ctx context.Context, bindingUUID string) ([]QMissingIpSanMetric, error) {
	var qMetrics []QMissingIpSanMetric

	if bindingUUID != "" {
		for _, metric := range mock.MissingIpSanRecords {
			if metric.BindingUUID == bindingUUID {
				qMetrics = append(qMetrics, metric)
			}
		}
	} else {
		qMetrics = mock.MissingIpSanRecords
	}

	return qMetrics, nil
}

func (mock *Mockstore) QueryServiceTypes(ctx context.Context, name string) ([]QServiceType, error) {

	var qServices []QServiceType

	if name != "" {
		for _, service := range mock.ServiceTypes {
			if service.Name == name {
				qServices = append(qServices, service)
			}
		}
	} else {
		qServices = mock.ServiceTypes
	}

	return qServices, nil
}

func (mock *Mockstore) QueryServiceTypesByUUID(ctx context.Context, uuid string) ([]QServiceType, error) {

	var qServices []QServiceType

	for _, service := range mock.ServiceTypes {
		if service.UUID == uuid {
			qServices = append(qServices, service)
		}
	}

	return qServices, nil
}

func (mock *Mockstore) QueryApiKeyAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QApiKeyAuthMethod, error) {

	var qAuthms []QApiKeyAuthMethod
	var err error
	var ok bool
	var qAuthm *QApiKeyAuthMethod

	if serviceUUID == "" && host == "" {
		for _, am := range mock.AuthMethods {
			if qAuthm, ok = am.(*QApiKeyAuthMethod); ok {
				qAuthms = append(qAuthms, *qAuthm)
			}
		}
		return qAuthms, nil
	}

	for _, am := range mock.AuthMethods {
		if qAuthm, ok = am.(*QApiKeyAuthMethod); ok {
			if qAuthm.ServiceUUID == serviceUUID && qAuthm.Host == host {
				qAuthms = append(qAuthms, *qAuthm)
			}
		}
	}

	return qAuthms, err

}

func (mock *Mockstore) QueryHeadersAuthMethods(ctx context.Context, serviceUUID string, host string) ([]QHeadersAuthMethod, error) {

	var qAuthms []QHeadersAuthMethod
	var err error
	var ok bool
	var qAuthm *QHeadersAuthMethod

	if serviceUUID == "" && host == "" {
		for _, am := range mock.AuthMethods {
			if qAuthm, ok = am.(*QHeadersAuthMethod); ok {
				qAuthms = append(qAuthms, *qAuthm)
			}
		}
		return qAuthms, nil
	}

	for _, am := range mock.AuthMethods {
		if qAuthm, ok = am.(*QHeadersAuthMethod); ok {
			if qAuthm.ServiceUUID == serviceUUID && qAuthm.Host == host {
				qAuthms = append(qAuthms, *qAuthm)
			}
		}
	}

	return qAuthms, err

}

func (mock *Mockstore) QueryBindingsByAuthID(ctx context.Context, authID string, serviceUUID string, host string, authType string) ([]QBinding, error) {

	var qBindings []QBinding

	for _, qBinding := range mock.Bindings {
		if qBinding.AuthIdentifier == authID && qBinding.Host == host && qBinding.ServiceUUID == serviceUUID && qBinding.AuthType == authType {
			qBindings = append(qBindings, qBinding)
		}
	}

	return qBindings, nil
}

func (mock *Mockstore) QueryBindingsByUUIDAndName(ctx context.Context, uuid, name string) ([]QBinding, error) {

	var qBindings []QBinding

	if uuid != "" && name == "" {
		for _, qBinding := range mock.Bindings {
			if qBinding.UUID == uuid {
				qBindings = append(qBindings, qBinding)
			}
		}
	}

	if uuid == "" && name != "" {
		for _, qBinding := range mock.Bindings {
			if qBinding.Name == name {
				qBindings = append(qBindings, qBinding)
			}
		}
	}

	if uuid != "" && name != "" {
		for _, qBinding := range mock.Bindings {
			if qBinding.UUID == uuid && qBinding.Name == name {
				qBindings = append(qBindings, qBinding)
			}
		}
	}

	return qBindings, nil
}

func (mock *Mockstore) QueryBindings(ctx context.Context, serviceUUID string, host string) ([]QBinding, error) {

	var qBindings []QBinding

	if serviceUUID == "" && host == "" {
		qBindings = mock.Bindings
		return qBindings, nil
	}

	for _, qBinding := range mock.Bindings {
		if qBinding.ServiceUUID == serviceUUID && qBinding.Host == host {
			qBindings = append(qBindings, qBinding)
		}
	}

	return qBindings, nil
}

func (mock *Mockstore) InsertAuthMethod(ctx context.Context, am QAuthMethod) error {

	mock.AuthMethods = append(mock.AuthMethods, am)

	return nil
}

func (mock *Mockstore) InsertServiceType(ctx context.Context, name string, hosts []string, authTypes []string, authMethod string, uuid string, createdOn string, sType string) (QServiceType, error) {

	qService := QServiceType{Name: name, Hosts: hosts, AuthTypes: authTypes, AuthMethod: authMethod, UUID: uuid, CreatedOn: createdOn, Type: sType}

	mock.ServiceTypes = append(mock.ServiceTypes, qService)

	return qService, nil
}

func (mock *Mockstore) InsertBinding(ctx context.Context, name string, serviceUUID string, host string, uuid string, authID string, uniqueKey string, authType string) (QBinding, error) {

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

	mock.Bindings = append(mock.Bindings, qBinding)

	return qBinding, nil

}

func (mock *Mockstore) UpdateBinding(ctx context.Context, original QBinding, updated QBinding) (QBinding, error) {

	// find the  binding in the list and replace it
	for idx, qb := range mock.Bindings {
		if qb == original {
			mock.Bindings[idx] = updated
			break
		}
	}

	return updated, nil
}

func (mock *Mockstore) UpdateServiceType(ctx context.Context, original QServiceType, updated QServiceType) (QServiceType, error) {

	// find the service type in the list and replace it
	for idx, sv := range mock.ServiceTypes {
		if reflect.DeepEqual(original, sv) { // requires DeepEqual because structs with []string as fields can't be compared
			mock.ServiceTypes[idx] = updated
			break
		}
	}

	return updated, nil
}

func (mock *Mockstore) UpdateAuthMethod(ctx context.Context, original QAuthMethod, updated QAuthMethod) (QAuthMethod, error) {

	// find the auth method in the list and replace it
	for idx, sv := range mock.AuthMethods {
		if reflect.DeepEqual(original, sv) {
			mock.AuthMethods[idx] = updated
			break
		}
	}

	return updated, nil
}

func (mock *Mockstore) DeleteServiceTypeByUUID(ctx context.Context, uuid string) error {

	for idx, st := range mock.ServiceTypes {
		if st.UUID == uuid {
			mock.ServiceTypes = append(mock.ServiceTypes[:idx], mock.ServiceTypes[idx+1:]...)
			break
		}
	}

	return nil
}

// DeleteBinding removes the given qBinding from the slice of bindings
func (mock *Mockstore) DeleteBinding(ctx context.Context, qBinding QBinding) error {

	// find the  binding in the list and replace it
	for idx, qb := range mock.Bindings {
		if qb == qBinding {
			mock.Bindings = append(mock.Bindings[:idx], mock.Bindings[idx+1:]...)
			break
		}
	}

	return nil
}

func (mock *Mockstore) DeleteBindingByServiceUUID(ctx context.Context, serviceUUID string) error {

	var remainingBindings []QBinding

	// extract all the bindings that don't match the service's uuid
	for _, qb := range mock.Bindings {
		if qb.ServiceUUID != serviceUUID {
			remainingBindings = append(remainingBindings, qb)
		}
	}

	mock.Bindings = remainingBindings
	return nil
}

func (mock *Mockstore) DeleteAuthMethod(ctx context.Context, am QAuthMethod) error {

	// loop through the slice of auth methods
	// and delete

	for idx, ami := range mock.AuthMethods {
		if reflect.DeepEqual(ami, am) {
			mock.AuthMethods = append(mock.AuthMethods[:idx], mock.AuthMethods[idx+1:]...)
			break
		}
	}

	return nil

}

func (mock *Mockstore) DeleteAuthMethodByServiceUUID(ctx context.Context, serviceUUID string) error {

	var remainingQAM []QAuthMethod

	for _, qam := range mock.AuthMethods {
		i, _ := utils.GetFieldValueByName(qam, "ServiceUUID")
		if i.(string) != serviceUUID {
			remainingQAM = append(remainingQAM, qam)
		}
	}
	mock.AuthMethods = remainingQAM
	return nil
}
