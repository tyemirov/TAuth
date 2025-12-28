package web

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

const (
	demoConfigCacheControl    = "no-store, no-cache, must-revalidate, private"
	demoConfigPragma          = "no-cache"
	demoConfigNoSniff         = "nosniff"
	demoConfigJSContentType   = "application/javascript; charset=utf-8"
	demoConfigJSONContentType = "application/json; charset=utf-8"
)

// DemoConfig contains dynamic values exposed to the demo frontend.
type DemoConfig struct {
	GoogleClientID string `json:"googleClientId"`
}

// ServeDemoConfig emits a JavaScript payload that hydrates window.__TAUTH_DEMO_CONFIG.
func ServeDemoConfig(contextGin *gin.Context, configuration DemoConfig) {
	quotedClientID := strconv.Quote(configuration.GoogleClientID)
	script := fmt.Sprintf(`(function(){var config=Object.freeze({"googleClientId":%s});window.__TAUTH_DEMO_CONFIG=config;if(typeof window==="undefined"||typeof document==="undefined"){return;}var assignClientId=function(){var host=document.getElementById("g_id_onload");if(host&&config.googleClientId){host.setAttribute("data-client_id",config.googleClientId);}};if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",assignClientId,{once:true});}else{assignClientId();}})();`, quotedClientID)

	applyDemoConfigHeaders(contextGin, demoConfigJSContentType)
	contextGin.String(http.StatusOK, script)
}

// ServeDemoConfigJSON emits a JSON payload for demo configuration.
func ServeDemoConfigJSON(contextGin *gin.Context, configuration DemoConfig) {
	applyDemoConfigHeaders(contextGin, demoConfigJSONContentType)
	contextGin.JSON(http.StatusOK, configuration)
}

func applyDemoConfigHeaders(contextGin *gin.Context, contentType string) {
	contextGin.Header("Content-Type", contentType)
	contextGin.Header("Cache-Control", demoConfigCacheControl)
	contextGin.Header("Pragma", demoConfigPragma)
	contextGin.Header("X-Content-Type-Options", demoConfigNoSniff)
}
