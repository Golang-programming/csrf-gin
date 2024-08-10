package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RegisterController(ctx *gin.Context) {
	var registerInput = &RegisterInput{}
	if err := ctx.BindJSON(&registerInput); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userId, err := RegisterService(registerInput)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	CreateTokensService(ctx, userId)
}

func LoginController(ctx *gin.Context) {
	var loginInput = &LoginInput{}
	if err := ctx.BindJSON(&loginInput); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userId, err := UserService(loginInput)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	CreateTokensService(ctx, userId)
}

func LogoutController(ctx *gin.Context) {
	LogoutService(ctx)
}
