package utils

import (
	"time"

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

func NillifyTokenCookies(ctx *gin.Context) {
	expireAt := time.Now().Add(-1000 * time.Hour)
	maxAge := int(time.Since(expireAt).Seconds()) // Calculate maxAge as the number of seconds since expireAt

	ctx.SetCookie("accessToken", "", maxAge, "", "", true, true)
	ctx.SetCookie("refreshToken", "", maxAge, "", "", true, true)
}

func SetCookies(ctx *gin.Context, accessToken, refreshToken string) {
	ctx.SetCookie("accessToken", accessToken, 0, "", "", true, true)
	ctx.SetCookie("refreshToken", refreshToken, 0, "", "", true, true)
}

func GenerateCSRFSecret() string {
	return utils.GenerateRandomString(32)
}

func CheckPasswordHash(password, hashePassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashePassword), []byte(password))
}
