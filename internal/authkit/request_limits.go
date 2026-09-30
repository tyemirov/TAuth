package authkit

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

const maximumAuthBodyBytes = 32 * 1024

func boundedAuthBody(ctx *gin.Context) {
	if ctx.Request.Body == nil {
		ctx.Next()
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maximumAuthBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			ctx.AbortWithStatus(http.StatusRequestEntityTooLarge)
		} else {
			ctx.AbortWithStatus(http.StatusBadRequest)
		}
		return
	}
	ctx.Request.Body = io.NopCloser(bytes.NewReader(data))
	ctx.Next()
}
