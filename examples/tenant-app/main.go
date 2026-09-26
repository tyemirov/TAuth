// Run this customer API behind HTTPS at the configured API origin.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/tyemirov/tauth/internal/customerapp"
)

func main() {
	handler, err := customerapp.New(customerapp.Config{UpstreamOrigin: os.Getenv("TAUTH_UPSTREAM_ORIGIN"), APIOrigin: os.Getenv("TAUTH_API_ORIGIN"), FrontendOrigin: os.Getenv("TAUTH_FRONTEND_ORIGIN"), TenantID: os.Getenv("TAUTH_TENANT_ID"), SessionCookie: os.Getenv("TAUTH_SESSION_COOKIE"), SessionKeyBase64: os.Getenv("TAUTH_SESSION_KEY_BASE64")}, http.DefaultTransport)
	if err != nil {
		log.Fatal(err)
	}
	address := os.Getenv("CUSTOMER_API_LISTEN_ADDR")
	if address == "" {
		log.Fatal("CUSTOMER_API_LISTEN_ADDR is required")
	}
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute}
	log.Fatal(server.ListenAndServe())
}
