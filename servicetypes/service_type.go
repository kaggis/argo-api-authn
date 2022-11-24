package servicetypes

import (
	"context"
	"fmt"

	"github.com/ARGOeu/argo-api-authn/config"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	uuid2 "github.com/satori/go.uuid"
)

type ServiceType struct {
	Name       string   `json:"name" required:"true"`
	Hosts      []string `json:"hosts" required:"true"`
	AuthTypes  []string `json:"auth_types" required:"true"`
	AuthMethod string   `json:"auth_method" required:"true"`
	UUID       string   `json:"uuid"`
	CreatedOn  string   `json:"created_on"`
	UpdatedOn  string   `json:"updated_on,omitempty"`
	Type       string   `json:"type" required:"true"`
}

// TempServiceType is a struct to be used as an intermediate node when updating a service type
// containing only the `allowed to be updated fields`
type TempServiceType struct {
	Name       string   `json:"name"`
	Hosts      []string `json:"hosts"`
	AuthTypes  []string `json:"auth_types"`
	AuthMethod string   `json:"auth_method"`
}

type ServiceTypesList struct {
	ServiceTypes []ServiceType `json:"service_types"`
}

// CreateServiceType creates a new service type after validating the service
func CreateServiceType(ctx context.Context, service ServiceType, store stores.Store, cfg config.Config) (ServiceType, error) {

	var qService stores.QServiceType
	var err error

	// validate the service type
	if err = service.Validate(store, cfg); err != nil {
		return ServiceType{}, err
	}

	// check that the name of the service type is unique
	if err = ExistsWithName(ctx, service.Name, store); err != nil {
		return ServiceType{}, err
	}

	// generate UUID
	uuid := uuid2.NewV4().String()

	// insert the service type
	if qService, err = store.InsertServiceType(ctx, service.Name, service.Hosts, service.AuthTypes, service.AuthMethod, uuid, utils.ZuluTimeNow(), service.Type); err != nil {
		return ServiceType{}, err
	}

	// convert the qService to a ServiceType
	if err = utils.CopyFields(qService, &service); err != nil {
		err = utils.APIErrDatabase(err.Error())
		return ServiceType{}, err
	}

	return service, err
}

// Validate validates the contents of the service type's fields
func (s *ServiceType) Validate(store stores.Store, cfg config.Config) error {

	var err error

	// check if all required field have been provided
	if err = utils.ValidateRequired(*s); err != nil {
		err := utils.APIErrEmptyRequiredField("service-type", err.Error())
		return err
	}

	if len(s.Hosts) == 0 {
		err = utils.APIErrEmptyRequiredField("service-type", utils.GenericEmptyRequiredField("hosts").Error())
		return err
	}

	// check if the authentication methods are supported
	if err = s.hasValidAuthMethod(cfg); err != nil {
		return err
	}

	// check if the authentication type is supported
	if err = s.hasValidAuthTypes(cfg); err != nil {
		return err
	}

	// check the type
	if err = s.IsOfValidType(cfg); err != nil {
		return err
	}

	return nil
}

// ExistsWithName checks if a service type with the given name already exists
func ExistsWithName(ctx context.Context, name string, store stores.Store) error {

	var err error
	var qServices []stores.QServiceType

	if qServices, err = store.QueryServiceTypes(ctx, name); err != nil {
		return err
	}

	if len(qServices) > 0 {
		err = utils.APIErrConflict("service-type", "name", name)
		return err
	}

	return nil
}

// FindServiceTypeByName queries the datastore to find a service type associated with the provided argument name
func FindServiceTypeByName(ctx context.Context, name string, store stores.Store) (ServiceType, error) {

	var qServices []stores.QServiceType
	var service ServiceType
	var err error

	if qServices, err = store.QueryServiceTypes(ctx, name); err != nil {
		return ServiceType{}, err
	}

	if len(qServices) == 0 {
		err = utils.APIErrNotFound("Service-type")
		return ServiceType{}, err
	}

	if len(qServices) > 1 {
		err = utils.APIErrDatabase("Multiple service-types with the same name: " + name)
		return ServiceType{}, err
	}

	if err := utils.CopyFields(qServices[0], &service); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return ServiceType{}, err
	}

	return service, err
}

// FindServiceTypeByUUID queries the datastore to find a service type associated with the provided argument uuid
func FindServiceTypeByUUID(ctx context.Context, uuid string, store stores.Store) (ServiceType, error) {

	var qServices []stores.QServiceType
	var service ServiceType
	var err error

	if qServices, err = store.QueryServiceTypesByUUID(ctx, uuid); err != nil {
		return ServiceType{}, err
	}

	if len(qServices) == 0 {
		err = utils.APIErrNotFound("Service-type")
		return ServiceType{}, err
	}

	if len(qServices) > 1 {
		err = utils.APIErrDatabase("Multiple service-types with the same uuid: " + uuid)
		return ServiceType{}, err
	}

	if err := utils.CopyFields(qServices[0], &service); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return ServiceType{}, err
	}

	return service, err
}

// FindAllServiceTypes returns all the service types from the datastore
func FindAllServiceTypes(ctx context.Context, store stores.Store) (ServiceTypesList, error) {

	var qServices []stores.QServiceType
	var services = []ServiceType{}
	var err error

	if qServices, err = store.QueryServiceTypes(ctx, ""); err != nil {
		return ServiceTypesList{ServiceTypes: services}, err
	}

	for _, qs := range qServices {
		_service := &ServiceType{}
		if err := utils.CopyFields(qs, _service); err != nil {
			err = utils.APIGenericInternalError(err.Error())
			return ServiceTypesList{ServiceTypes: services}, err
		}
		services = append(services, *_service)
	}

	return ServiceTypesList{ServiceTypes: services}, err

}

// hsHost returns whether or not a host is associated with a service type
func (s *ServiceType) HasHost(host string) bool {

	flag := false
	for _, h := range s.Hosts {
		if h == host {
			flag = true
			break
		}
	}

	return flag
}

// hasValidAuthTypes checks whether or not the authentication types of a service type are supported
func (s *ServiceType) hasValidAuthTypes(cfg config.Config) error {

	var err error
	var flag bool

	if len(s.AuthTypes) == 0 {
		err = utils.APIErrUnsupportedContent("auth_types", "empty", fmt.Sprintf("Supported:%v", cfg.SupportedAuthTypes))
		return err
	}

	for _, am := range s.AuthTypes {
		flag = false
		for _, cam := range cfg.SupportedAuthTypes {
			if am == cam {
				flag = true
				break
			}
		}
		if !flag {
			err = utils.APIErrUnsupportedContent("auth_types", am, fmt.Sprintf("Supported:%v", cfg.SupportedAuthTypes))
			return err
		}
	}
	return err
}

// hasValidAuthMethod checks whether or not the authentication method of a service type is supported
func (s *ServiceType) hasValidAuthMethod(cfg config.Config) error {

	var err error
	for _, am := range cfg.SupportedAuthMethods {
		if am == s.AuthMethod {
			return err
		}
	}

	err = utils.APIErrUnsupportedContent("auth_method", s.AuthMethod, fmt.Sprintf("Supported:%v", cfg.SupportedAuthMethods))
	return err
}

// SupportsAuthType checks whether or not the service type wants to support that kind of auth type, e.g. x509
func (s *ServiceType) SupportsAuthType(authType string) error {

	var err error
	var flag bool

	for _, at := range s.AuthTypes {
		if at == authType {
			flag = true
			break
		}
	}

	if !flag {
		err = utils.APIErrUnsupportedContent("Auth type", authType, fmt.Sprintf("Supported:%v", s.AuthTypes))
		return err
	}

	return err

}

// IsOfValidType checks whether or not the type of a service type is supported
func (s *ServiceType) IsOfValidType(cfg config.Config) error {

	var err error
	for _, am := range cfg.SupportedServiceTypes {
		if am == s.Type {
			return err
		}
	}

	err = utils.APIErrUnsupportedContent("type", s.Type, fmt.Sprintf("Supported:%v", cfg.SupportedServiceTypes))
	return err
}

// UpdateServiceType updates a binding after validating its fields
func UpdateServiceType(ctx context.Context, original ServiceType, tempServiceType TempServiceType, store stores.Store, cfg config.Config) (ServiceType, error) {

	var err error
	var updated ServiceType
	var qOriginalSt stores.QServiceType
	var qUpdatedSt stores.QServiceType

	// created the updated service type, combining the fields from the original and the temporary
	if err := utils.CopyFields(original, &updated); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return ServiceType{}, err
	}

	if err := utils.CopyFields(tempServiceType, &updated); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return ServiceType{}, err
	}

	// validate the updated service type
	if err = updated.Validate(store, cfg); err != nil {
		return updated, err
	}

	// if there is an update happening to the name field, check if its unique
	if original.Name != tempServiceType.Name {
		if err = ExistsWithName(ctx, tempServiceType.Name, store); err != nil {
			return ServiceType{}, err
		}
	}

	updated.UpdatedOn = utils.ZuluTimeNow()

	// convert the original service type to a QServiceType
	if err := utils.CopyFields(original, &qOriginalSt); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return ServiceType{}, err
	}

	// convert the updated service type to a QServiceType
	if err := utils.CopyFields(updated, &qUpdatedSt); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return ServiceType{}, err
	}

	// update the service type
	if _, err = store.UpdateServiceType(ctx, qOriginalSt, qUpdatedSt); err != nil {
		err = &utils.APIError{Status: "INTERNAL SERVER ERROR", Code: 500, Message: err.Error()}
		return ServiceType{}, err
	}

	return updated, err
}

// DeleteServiceType deletes a service from the datastore as well as all of the other entities that are associated with it
func DeleteServiceType(ctx context.Context, serviceType ServiceType, store stores.Store) error {

	var err error

	// first delete all the bindings associated with the service type
	if err = store.DeleteBindingByServiceUUID(ctx, serviceType.UUID); err != nil {
		return err
	}

	// delete all the auth methods associated with the service type
	if err = store.DeleteAuthMethodByServiceUUID(ctx, serviceType.UUID); err != nil {
		return err
	}

	// finally delete the service type
	if err = store.DeleteServiceTypeByUUID(ctx, serviceType.UUID); err != nil {
		return err
	}

	return err
}
