package bindings

import (
	"context"
	"fmt"

	"github.com/ARGOeu/argo-api-authn/servicetypes"
	"github.com/ARGOeu/argo-api-authn/stores"
	"github.com/ARGOeu/argo-api-authn/utils"
	uuid2 "github.com/satori/go.uuid"
)

type Binding struct {
	Name           string `json:"name" required:"true"`
	ServiceUUID    string `json:"service_uuid" required:"true"`
	Host           string `json:"host" required:"true"`
	UUID           string `json:"uuid"`
	AuthIdentifier string `json:"auth_identifier" required:"true"`
	UniqueKey      string `json:"unique_key" required:"true"`
	AuthType       string `json:"auth_type" required:"true"`
	CreatedOn      string `json:"created_on,omitempty"`
	UpdatedOn      string `json:"updated_on,omitempty"`
	LastAuth       string `json:"last_auth,omitempty"`
}

// TempUpdateBinding is a struct to be used as an intermediate node when updating a binding
// containing only the `allowed to be updated fields`
type TempUpdateBinding struct {
	Name           string `json:"name"`
	ServiceUUID    string `json:"service_uuid"`
	Host           string `json:"host"`
	AuthIdentifier string `json:"auth_identifier"`
	AuthType       string `json:"auth_type"`
	UniqueKey      string `json:"unique_key"`
}

type BindingList struct {
	Bindings []Binding `json:"bindings"`
}

// CreateBinding creates a new binding after validating its context
func CreateBinding(ctx context.Context, binding Binding, store stores.Store) (Binding, error) {

	var qBinding stores.QBinding
	var err error

	// validate the binding
	if err = binding.Validate(ctx, store); err != nil {
		return binding, err
	}

	// check if a binding with same auth identifier already exists under the same service type and host
	if err := ExistsWithAuthID(ctx, binding.AuthIdentifier, binding.ServiceUUID, binding.Host, binding.AuthType, store); err != nil {
		return binding, err
	}

	// check if a binding with the same name exists
	if err := ExistsWithName(ctx, binding.Name, store); err != nil {
		return binding, err
	}

	// generate uuid
	uuid := uuid2.NewV4().String()

	if qBinding, err = store.InsertBinding(ctx, binding.Name, binding.ServiceUUID, binding.Host, uuid, binding.AuthIdentifier, binding.UniqueKey, binding.AuthType); err != nil {
		return binding, err
	}

	if err = utils.CopyFields(qBinding, &binding); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return binding, err
	}

	return binding, err
}

// Validate performs various checks on the fields of a binding
func (binding *Binding) Validate(ctx context.Context, store stores.Store) error {

	var err error
	var ok bool
	var serviceType servicetypes.ServiceType

	// check if all required field have been provided
	if err = utils.ValidateRequired(*binding); err != nil {
		err := utils.APIErrEmptyRequiredField("binding", err.Error())
		return err
	}

	// check if the ServiceUUID is aligned with an existing service type
	if serviceType, err = servicetypes.FindServiceTypeByUUID(ctx, binding.ServiceUUID, store); err != nil {
		return err
	}

	// check if the provided host is associated with the given service type
	if ok = serviceType.HasHost(binding.Host); ok == false {
		err = utils.APIErrNotFound("Host")
		return err
	}

	// check if the auth type of the bindings is supported by the service type it belongs to
	if err = serviceType.SupportsAuthType(binding.AuthType); err != nil {
		err = utils.APIErrUnsupportedContent("Auth type", binding.AuthType,
			fmt.Sprintf("Supported:%v", serviceType.AuthTypes))
		return err
	}

	return nil
}

// ExistsWithAuthID checks if a binding with the provided auth identifier already exists
// under the given service type and host
func ExistsWithAuthID(ctx context.Context, authID string, serviceUUID string, host string, authType string, store stores.Store) error {

	var err error

	// check if the given authID doesn't already exist under the given service type and host
	// first check for all the other errors regrading bindings
	if _, err = FindBindingByAuthID(ctx, authID, serviceUUID, host, authType, store); err != nil {
		if err.Error() != "Binding was not found" {
			return err
		}
	}

	// if the error is nil, it means the function found and returned a binding
	if err == nil {
		err = utils.APIErrConflict("binding", "auth_identifier", authID)
		return err
	}

	return nil
}

// ExistsWithName checks if a binding with the provided name already exists
func ExistsWithName(ctx context.Context, name string, store stores.Store) error {

	var err error

	// check if the given name is taken
	if _, err = FindBindingByUUIDAndName(ctx, "", name, store); err != nil {
		if err.Error() != "Binding was not found" {
			return err
		}
	}

	// if the error is nil, it means the function found and returned a binding
	if err == nil {
		err = utils.APIErrConflict("binding", "name", name)
		return err
	}

	return nil
}

// FindBindingByAuthID queries the datastore and returns a binding based on the given auth identifier, service and host
func FindBindingByAuthID(ctx context.Context, authID string, serviceUUID string, host string, authType string, store stores.Store) (Binding, error) {

	var qBindings []stores.QBinding
	var err error
	var binding Binding

	if qBindings, err = store.QueryBindingsByAuthID(ctx, authID, serviceUUID, host, authType); err != nil {
		return Binding{}, err
	}

	if len(qBindings) > 1 {
		err = utils.APIErrDatabase("More than 1 bindings found under the service type: " + serviceUUID + " and host: " + host + " using the same AuthIdentifier: " + authID)
		return Binding{}, err
	}

	if len(qBindings) == 0 {
		err = utils.APIErrNotFound("Binding")
		return Binding{}, err
	}

	if err = utils.CopyFields(qBindings[0], &binding); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return binding, err
	}

	return binding, err
}

// FindAllBindings returns all the bindings in the service
func FindAllBindings(ctx context.Context, store stores.Store) (BindingList, error) {

	var err error
	var qBindings []stores.QBinding
	var bindings = []Binding{}

	if qBindings, err = store.QueryBindings(ctx, "", ""); err != nil {
		return BindingList{Bindings: []Binding{}}, err
	}

	// convert the QBindings to Bindings
	for _, qb := range qBindings {
		_binding := &Binding{}
		if err := utils.CopyFields(qb, _binding); err != nil {
			err = utils.APIGenericInternalError(err.Error())
			return BindingList{Bindings: []Binding{}}, err
		}
		bindings = append(bindings, *_binding)
	}

	return BindingList{Bindings: bindings}, err

}

// FindBindingsByServiceTypeAndHost returns all the bindings of a specific service type and host
func FindBindingsByServiceTypeAndHost(ctx context.Context, serviceUUID string, host string, store stores.Store) (BindingList, error) {

	var qBindings []stores.QBinding
	var bindings = []Binding{}
	var err error

	if qBindings, err = store.QueryBindings(ctx, serviceUUID, host); err != nil {
		return BindingList{Bindings: []Binding{}}, err
	}

	for _, qb := range qBindings {
		_binding := &Binding{}
		if err := utils.CopyFields(qb, _binding); err != nil {
			err = utils.APIGenericInternalError(err.Error())
			return BindingList{Bindings: []Binding{}}, err
		}
		bindings = append(bindings, *_binding)
	}

	return BindingList{Bindings: bindings}, err
}

// FindBindingByUUIDAndName returns the binding associated with the provided uuid and/or name
func FindBindingByUUIDAndName(ctx context.Context, uuid, name string, store stores.Store) (Binding, error) {

	var qBindings []stores.QBinding
	var err error
	var binding Binding

	if qBindings, err = store.QueryBindingsByUUIDAndName(ctx, uuid, name); err != nil {
		return Binding{}, err
	}

	if uuid != "" {
		if len(qBindings) > 1 {
			err = utils.APIErrDatabase("More than 1 Bindings found with the same UUID: " + uuid)
			return Binding{}, err
		}
	}

	if len(qBindings) == 0 {
		err = utils.APIErrNotFound("Binding")
		return Binding{}, err
	}

	if err = utils.CopyFields(qBindings[0], &binding); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return binding, err
	}

	return binding, err
}

// UpdateBinding updates a binding after validating its fields
func UpdateBinding(ctx context.Context, original Binding, tempBind TempUpdateBinding, store stores.Store) (Binding, error) {

	var err error
	var updated Binding
	var qOriginalBinding stores.QBinding
	var qUpdatedBinding stores.QBinding

	// created the updated binding, combining the fields from the original and the temporary
	if err := utils.CopyFields(original, &updated); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return Binding{}, err
	}

	if err := utils.CopyFields(tempBind, &updated); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return Binding{}, err
	}

	// validate the updated binding
	if err = updated.Validate(ctx, store); err != nil {
		return updated, err
	}

	// if there is a new auth identifier provided, check whether it already exists
	if original.AuthIdentifier != updated.AuthIdentifier {
		// check if a binding with same authID already exists under the same service type and host
		if err := ExistsWithAuthID(ctx, updated.AuthIdentifier, updated.ServiceUUID, updated.Host, updated.AuthType, store); err != nil {
			return Binding{}, err
		}

	}

	// if there is a new name provided, check whether it already exists
	if original.Name != updated.Name {
		// check if a binding with same name already exists
		if err := ExistsWithName(ctx, updated.Name, store); err != nil {
			return Binding{}, err
		}

	}

	// convert the original binding to a QBinding
	if err := utils.CopyFields(original, &qOriginalBinding); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return Binding{}, err
	}

	updated.UpdatedOn = utils.ZuluTimeNow()

	// convert the updated binding to a QBinding
	if err := utils.CopyFields(updated, &qUpdatedBinding); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return Binding{}, err
	}

	// update the binding
	if _, err = store.UpdateBinding(ctx, qOriginalBinding, qUpdatedBinding); err != nil {
		err = &utils.APIError{Status: "INTERNAL SERVER ERROR", Code: 500, Message: err.Error()}
		return Binding{}, err
	}

	return updated, err
}

// DeleteBinding deletes the given binding from the store
func DeleteBinding(ctx context.Context, binding Binding, store stores.Store) error {

	var err error
	var qBinding stores.QBinding

	// convert the binding Binding to a QBinding
	if err = utils.CopyFields(binding, &qBinding); err != nil {
		err = utils.APIGenericInternalError(err.Error())
		return err
	}

	if err = store.DeleteBinding(ctx, qBinding); err != nil {
		return err
	}

	return err

}
