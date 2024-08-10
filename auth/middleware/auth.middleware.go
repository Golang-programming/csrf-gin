package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-programming/csrf-gin-mysql/auth/utils"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		accessToken, refreshToken := retriveToken(ctx)
		csrfSecret := utils.GrabCSRFFromContext(ctx)

		ctx.Next()
	}
}

func retriveToken(ctx *gin.Context) (accessToken, refreshToken string) {
	var err error

	accessToken, err = ctx.Cookie("accessToken")
	if err == http.ErrNoCookie {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized specified"})
		ctx.Abort()
	}
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		ctx.Abort()
	}

	refreshToken, err = ctx.Cookie("refreshToken")

	if err == http.ErrNoCookie {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized specified"})
		ctx.Abort()
	}
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		ctx.Abort()
	}

	return
}
