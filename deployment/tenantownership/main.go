// The deployment migration is built and run separately from the TAuth service.
package main

import (
	"github.com/tyemirov/tauth/deployment/migrations"
	"os"
)

func main() {
	if err := migrations.NewCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
