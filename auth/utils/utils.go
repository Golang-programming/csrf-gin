package utils

import (
	"github.com/gin-gonic/gin"
	utils "github.com/golang-programming/csrf-gin-mysql/utils"
	"golang.org/x/crypto/bcrypt"
)

func GrabCSRFFromContext(ctx *gin.Context) string {
	csrfFromForm := ctx.Request.Form.Get("X-CSRF-Token")

	if csrfFromForm != "" {
		return csrfFromForm
	} else {
		return ctx.GetHeader("X-CSRF-Token")
	}
}

func GenerateCSRFSecret() string {
	return utils.GenerateRandomString(32)
}

func CheckPasswordHash(password, hashePassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashePassword), []byte(password))
}
