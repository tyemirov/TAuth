package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// DemoConfig contains dynamic values exposed to the demo frontend.
type DemoConfig struct {
	GoogleClientID string
	BaseURL        string
}

// ServeDemoConfig emits a JavaScript payload that hydrates window.__TAUTH_DEMO_CONFIG.
func ServeDemoConfig(contextGin *gin.Context, configuration DemoConfig) {
	baseURL := configuration.BaseURL
	if strings.TrimSpace(baseURL) == "" {
		scheme := forwardedProto(contextGin.Request)
		host := contextGin.Request.Host
		if host == "" {
			host = "localhost"
		}
		baseURL = fmt.Sprintf("%s://%s", scheme, host)
	}
	payload := struct {
		GoogleClientID string `json:"googleClientId"`
		BaseURL        string `json:"baseUrl"`
	}{
		GoogleClientID: configuration.GoogleClientID,
		BaseURL:        baseURL,
	}

	encoded, encodeErr := json.Marshal(payload)
	if encodeErr != nil {
		contextGin.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "web.demo_config.encode_failed",
		})
		return
	}

	script := fmt.Sprintf(`(function(){var config=Object.freeze(%s);window.__TAUTH_DEMO_CONFIG=config;if(typeof window==="undefined"||typeof document==="undefined"){return;}var assignGoogleConfig=function(){var host=document.getElementById("g_id_onload");if(host&&config.googleClientId){host.setAttribute("data-client_id",config.googleClientId);}};if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",assignGoogleConfig,{once:true});}else{assignGoogleConfig();}})();`, string(encoded))

	contextGin.Header("Content-Type", "application/javascript; charset=utf-8")
	contextGin.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
	contextGin.Header("Pragma", "no-cache")
	contextGin.Header("X-Content-Type-Options", "nosniff")
	contextGin.String(http.StatusOK, script)
}

func forwardedProto(request *http.Request) string {
	if request == nil {
		return "https"
	}
	if headerValue := request.Header.Get("X-Forwarded-Proto"); headerValue != "" {
		return headerValue
	}
	if request.TLS != nil {
		return "https"
	}
	if request.URL != nil && request.URL.Scheme != "" {
		return request.URL.Scheme
	}
	return "http"
}
