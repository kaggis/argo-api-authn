package utils

import (
	"errors"
	"reflect"
	"strings"
	"time"
)

// ValidateRequired accepts an instance of any type and checks whether or not all fields are filled
func ValidateRequired(instance interface{}) error {

	v := reflect.ValueOf(instance)

	for i := 0; i < v.NumField(); i++ {

		// Check if the field's exported otherwise .Interface() will panic
		if v.Type().Field(i).PkgPath != "" {
			continue
		}

		// check if the field has the required tag
		if v.Type().Field(i).Tag.Get("required") != "true" {
			continue
		}
		fieldValue := v.Field(i).Interface()
		zeroFieldValue := reflect.Zero(reflect.TypeOf(v.Field(i).Interface())).Interface()
		if reflect.DeepEqual(fieldValue, zeroFieldValue) {
			return GenericEmptyRequiredField(v.Type().Field(i).Tag.Get("json"))
		}
	}
	return nil
}

// GetFieldValueByName retrieves the value of a specified field from the provided instance
func GetFieldValueByName(instance interface{}, fieldName string) (interface{}, error) {

	var v reflect.Value
	var flv reflect.Value

	// Check if the field's name is capitalized to make sure its exported otherwise .Interface() will panic
	if !IsCapitalized(fieldName) {
		return nil, errors.New("you are trying to access an unexported field")
	}

	v = reflect.ValueOf(instance)

	// check if the provided argument is a pointer or not
	if v.Kind() == reflect.Ptr {
		flv = v.Elem().FieldByName(fieldName)
	} else {
		flv = v.FieldByName(fieldName)
	}

	// check if the field exists
	zeroReflectValue := reflect.Value{}
	if reflect.DeepEqual(flv, zeroReflectValue) {
		return nil, errors.New("Field: " + fieldName + " has not been declared.")
	}

	// check if the field contains a value or its empty
	fieldValue := flv.Interface()
	zeroFieldValue := reflect.Zero(reflect.TypeOf(flv.Interface())).Interface()

	if reflect.DeepEqual(fieldValue, zeroFieldValue) {
		return nil, GenericEmptyRequiredField(fieldName)
	}

	// if everything is ok, return the value of the field
	return flv.Interface(), nil
}

// SetFieldValueByName assigns a value to the specified field of the given interface
func SetFieldValueByName(instance interface{}, fieldName string, value interface{}) error {

	var v reflect.Value
	var vf reflect.Value
	var flv reflect.Value

	// Check if the field's name is capitalized to make sure its exported otherwise .Interface() will panic
	if !IsCapitalized(fieldName) {
		return errors.New("you are trying to access an unexported field")
	}

	v = reflect.ValueOf(instance)
	vf = reflect.ValueOf(value)

	// it requires a pointer to a struct so its fields are addressable in order to be set through the Set() method
	if v.Kind() != reflect.Ptr {
		return errors.New("SetFieldValueByName needs a pointer to a struct")
	}

	flv = v.Elem().FieldByName(fieldName)

	// check if the field exists
	zeroReflectValue := reflect.Value{}
	if reflect.DeepEqual(flv, zeroReflectValue) {
		return errors.New("Field: " + fieldName + " has not been declared.")
	}

	// check if the field and value types match
	if flv.Type() != vf.Type() {
		return errors.New("type miss match between field and value")
	}

	// if everything is ok assign the value
	flv.Set(vf)

	return nil
}

// StructToMap converts a non nil struct to a map of map[string]interface{}
func StructToMap(instance interface{}) map[string]interface{} {

	if instance == nil {
		return nil
	}

	var fl reflect.StructField
	contents := make(map[string]interface{})

	v := reflect.ValueOf(instance)
	for i := 0; i < v.NumField(); i++ {
		fl = v.Type().Field(i)
		// Check if the field's exported otherwise .Interface() will panic
		if fl.PkgPath != "" {
			continue
		}
		contents[fl.Name] = v.Field(i).Interface()
	}

	return contents
}

// IsCapitalized returns whether or not not a string is capitalized
func IsCapitalized(str string) bool {

	if str == "" {
		return false
	}

	return string([]rune(str)[0]) == strings.ToUpper(string([]rune(str)[0])) // check for a capitalized name (in utf-8)
}

// CopyFields finds same named field between two structs and copies the values from one to an other
func CopyFields(from interface{}, to interface{}) error {

	iv := reflect.Value{} // zero reflect value
	fromV := reflect.ValueOf(from)
	toV := reflect.ValueOf(to)
	fl := reflect.StructField{}

	// it requires a pointer to a struct so its fields are addressable in order to be set through the Set() method
	if toV.Kind() != reflect.Ptr {
		return errors.New("CopyFields needs a pointer to a struct as a second argument")
	}

	for i := 0; i < fromV.NumField(); i++ {
		fl = fromV.Type().Field(i)
		if fl.PkgPath != "" {
			continue
		}
		if toV.Elem().FieldByName(fl.Name) != iv { // if the field with that name doesn't exist in the struct it will return a zero reflect value
			toV.Elem().FieldByName(fl.Name).Set(fromV.FieldByName(fl.Name))
		}
	}
	return nil
}

// ZuluTimeNow returns the current UTC time in zulu format
func ZuluTimeNow() string {
	return time.Now().UTC().Format(ZULU_FORM)
}
