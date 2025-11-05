package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// DemoConfig contains dynamic values exposed to the demo frontend.
type DemoConfig struct {
	GoogleClientID string
}

// ServeDemoConfig emits a JavaScript payload that hydrates window.__TAUTH_DEMO_CONFIG.
func ServeDemoConfig(contextGin *gin.Context, configuration DemoConfig) {
	payload := struct {
		GoogleClientID string `json:"googleClientId"`
	}{
		GoogleClientID: configuration.GoogleClientID,
	}

	encoded, encodeErr := json.Marshal(payload)
	if encodeErr != nil {
		contextGin.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "web.demo_config.encode_failed",
		})
		return
	}

	script := fmt.Sprintf(`(function(){var config=Object.freeze(%s);window.__TAUTH_DEMO_CONFIG=config;if(typeof window==="undefined"||typeof document==="undefined"){return;}var assignClientId=function(){var host=document.getElementById("g_id_onload");if(host&&config.googleClientId){host.setAttribute("data-client_id",config.googleClientId);}};if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",assignClientId,{once:true});}else{assignClientId();}})();`, string(encoded))

	contextGin.Header("Content-Type", "application/javascript; charset=utf-8")
	contextGin.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
	contextGin.Header("Pragma", "no-cache")
	contextGin.Header("X-Content-Type-Options", "nosniff")
	contextGin.String(http.StatusOK, script)
}
