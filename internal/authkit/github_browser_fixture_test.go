package authkit

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGitHubBrowserFixture(t *testing.T) {
	if os.Getenv("TAUTH_GITHUB_BROWSER_FIXTURE") != "1" {
		t.Skip("browser fixture runs through test-github-browser-server")
	}
	fixture := newGitHubHTTPFixture(t, true, true)
	config := fixture.login.sessions.registry.configs["github"]
	config.TenantOrigins = append(config.TenantOrigins, "https://other.example.com")
	fixture.login.sessions.registry.configs["github"] = config
	fixture.login.provider.authorizationEndpoint = fixture.provider.Server.URL + "/login/oauth/authorize"
	router := fixture.server.Config.Handler.(*gin.Engine)
	router.GET("/test/tauth.js", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "application/javascript")
		helper, err := os.Open("../../web/tauth.js")
		if err != nil {
			t.Error(err)
			ctx.Status(500)
			return
		}
		defer helper.Close()
		if _, err := io.Copy(ctx.Writer, helper); err != nil {
			t.Error(err)
		}
	})
	router.GET("/test/app", func(ctx *gin.Context) {
		ctx.Header("Content-Type", "text/html")
		ctx.String(http.StatusOK, `<!doctype html><html lang="en"><title>GitHub login test</title><button id="redirect">GitHub redirect</button><button id="popup">GitHub popup</button><button id="popup-other-origin">GitHub popup on another origin</button><output id="profile"></output><output id="error"></output><script src="/test/tauth.js"></script><script>
initAuthClient({baseUrl:location.origin,tenantId:"github",onAuthenticated:profile=>document.querySelector("#profile").textContent=JSON.stringify(profile),onAuthError:error=>document.querySelector("#error").textContent=error.message});
document.querySelector("#redirect").onclick=()=>startGitHubLogin().catch(error=>document.querySelector("#error").textContent=error.message);
document.querySelector("#popup-other-origin").onclick=()=>startGitHubLogin({mode:"popup",returnTo:"https://other.example.com/done"}).catch(error=>document.querySelector("#error").textContent=error.message);
document.querySelector("#popup").onclick=()=>startGitHubLogin({mode:"popup"}).catch(error=>document.querySelector("#error").textContent=error.message);
</script></html>`)
	})
	stop := make(chan struct{})
	var once sync.Once
	router.POST("/test/shutdown", func(ctx *gin.Context) { ctx.Status(204); once.Do(func() { close(stop) }) })
	fmt.Printf("GITHUB_BROWSER_FIXTURE %s\n", fixture.server.URL)
	<-stop
}
