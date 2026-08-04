package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HandleHealth reports that the TAuth HTTP process is ready to accept API requests.
func HandleHealth(contextGin *gin.Context) {
	contextGin.Status(http.StatusOK)
}
