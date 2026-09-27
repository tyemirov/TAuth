package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

var managementContract struct {
	sync.Once
	document map[string]any
	err      error
}

// Validate actual HTTP responses against the published management representation schemas.
func validateManagementResponse(t *testing.T, method, path string, status int, payload any) {
	t.Helper()
	managementContract.Do(func() {
		data, err := os.ReadFile("../../docs/openapi.yaml")
		if err != nil {
			managementContract.err = err
			return
		}
		managementContract.err = yaml.Unmarshal(data, &managementContract.document)
	})
	if managementContract.err != nil {
		t.Fatal(managementContract.err)
	}
	document := managementContract.document
	address, err := url.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	segments := strings.Split(address.Path, "/")
	var operation map[string]any
	for template, definition := range document["paths"].(map[string]any) {
		parts := strings.Split(template, "/")
		if len(parts) != len(segments) {
			continue
		}
		match := true
		for index, part := range parts {
			if part != segments[index] && !strings.HasPrefix(part, "{") {
				match = false
				break
			}
		}
		if match {
			operation, _ = definition.(map[string]any)[strings.ToLower(method)].(map[string]any)
			break
		}
	}
	if operation == nil {
		return
	} // Unsupported methods are checked through their Allow contract.
	responses := operation["responses"].(map[string]any)
	response, ok := responses[strconv.Itoa(status)].(map[string]any)
	if !ok {
		response, _ = responses["default"].(map[string]any)
	}
	if response == nil {
		t.Fatalf("undocumented management status %s %s %d", method, path, status)
	}
	response = resolveContractReference(document, response)
	content, ok := response["content"].(map[string]any)
	if !ok {
		t.Fatalf("missing response schema: %s %s", method, path)
	}
	schema := content["application/json"].(map[string]any)["schema"].(map[string]any)
	if err := checkContractValue(document, schema, payload); err != nil {
		t.Fatalf("%s %s response contract: %v", method, path, err)
	}
}
func resolveContractReference(document, schema map[string]any) map[string]any {
	if reference, ok := schema["$ref"].(string); ok {
		value := any(document)
		for _, part := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
			value = value.(map[string]any)[part]
		}
		return value.(map[string]any)
	}
	return schema
}
func checkContractValue(document, schema map[string]any, value any) error {
	schema = resolveContractReference(document, schema)
	if types, ok := schema["type"].([]any); ok {
		for _, kind := range types {
			copy := map[string]any{}
			for key, item := range schema {
				copy[key] = item
			}
			copy["type"] = kind
			if checkContractValue(document, copy, value) == nil {
				return nil
			}
		}
		return fmt.Errorf("value does not match %v", types)
	}
	switch schema["type"] {
	case "null":
		if value != nil {
			return fmt.Errorf("expected null")
		}
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("expected object")
		}
		if required, ok := schema["required"].([]any); ok {
			for _, field := range required {
				if _, exists := object[field.(string)]; !exists {
					return fmt.Errorf("missing %s", field)
				}
			}
		}
		properties, _ := schema["properties"].(map[string]any)
		for name, item := range object {
			if field, ok := properties[name].(map[string]any); ok {
				if err := checkContractValue(document, field, item); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
			} else if schema["additionalProperties"] == false {
				return fmt.Errorf("unexpected %s", name)
			}
		}
	case "array":
		values, ok := value.([]any)
		if !ok {
			return fmt.Errorf("expected array")
		}
		for _, item := range values {
			if err := checkContractValue(document, schema["items"].(map[string]any), item); err != nil {
				return err
			}
		}
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string")
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected boolean")
		}
	case "integer":
		if number, ok := value.(float64); !ok || number != float64(int64(number)) {
			return fmt.Errorf("expected integer")
		}
	}
	if constant, ok := schema["const"]; ok && !reflect.DeepEqual(constant, value) {
		return fmt.Errorf("wrong constant")
	}
	if choices, ok := schema["enum"].([]any); ok {
		for _, choice := range choices {
			if reflect.DeepEqual(choice, value) {
				return nil
			}
		}
		return fmt.Errorf("value is outside enum")
	}
	return nil
}
func TestConsoleOpenAPIReferences(t *testing.T) {
	data, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 {
		t.Fatal("empty contract")
	}
	var walk func(any)
	walk = func(value any) {
		switch item := value.(type) {
		case map[string]any:
			if reference, ok := item["$ref"].(string); ok {
				target := any(document)
				for _, part := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
					object, ok := target.(map[string]any)
					if !ok {
						t.Fatalf("invalid reference %s", reference)
					}
					target = object[part]
				}
				if target == nil {
					t.Fatalf("missing reference %s", reference)
				}
			}
			for _, child := range item {
				walk(child)
			}
		case []any:
			for _, child := range item {
				walk(child)
			}
		}
	}
	walk(document)
}
