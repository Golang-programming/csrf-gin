package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	auth "github.com/golang-programming/csrf-gin-mysql/auth"
	"github.com/golang-programming/csrf-gin-mysql/auth/utils"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		accessToken, refreshToken := retriveTokens(ctx)
		csrfSecret := utils.GrabCSRFFromContext(ctx)

		newAccessTokenStr, newRefreshTokenStr, newCSRFSecret, err := auth.CheckAndRefreshTokens(accessToken, refreshToken, csrfSecret)

		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			ctx.Abort()
		}

		utils.SetCookies(ctx, newAccessTokenStr, newRefreshTokenStr)
		ctx.Header("X-CSRF-Token", newCSRFSecret)
		ctx.JSON(http.StatusOK, gin.H{"success": true})

		ctx.Next()
	}
}

func retriveTokens(ctx *gin.Context) (string, string) {
	accesstoken, err := ctx.Cookie("accessToken")
	if err == http.ErrNoCookie {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized specified"})
		ctx.Abort()
	}
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		ctx.Abort()
	}

	refreshToken, err := ctx.Cookie("refreshToken")

	if err == http.ErrNoCookie {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized specified"})
		ctx.Abort()
	}
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		ctx.Abort()
	}

	return accesstoken, refreshToken
}
