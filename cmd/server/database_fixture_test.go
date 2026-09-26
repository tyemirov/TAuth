package main

import (
	"os"
	"testing"

	"github.com/tyemirov/tauth/internal/appconfig"
	"github.com/tyemirov/tauth/internal/testconfig"
	"gopkg.in/yaml.v3"
)

func TestDatabaseFixture(t *testing.T) {
	sourcePath := os.Getenv("TAUTH_TEST_SOURCE")
	if sourcePath == "" {
		t.Skip("selected by the container integration target")
	}
	source, err := appconfig.LoadImportSource(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	source.Server.DatabaseURL = "sqlite://" + os.Getenv("TAUTH_TEST_DATABASE")
	service := testconfig.Prepare(t, *source)
	service.Server.DatabaseURL = os.Getenv("TAUTH_TEST_RUNTIME_DATABASE_URL")
	encoded, err := yaml.Marshal(service)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(os.Getenv("TAUTH_TEST_SERVICE"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
