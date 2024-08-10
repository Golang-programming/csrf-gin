package auth

import (
	"crypto/rsa"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/golang-programming/csrf-gin-mysql/database"
	"github.com/golang-programming/csrf-gin-mysql/utils"
)

var (
	// verifyKey *rsa.PublicKey
	signKey *rsa.PrivateKey
)

func CreateRefreshTokenString(userId, csrfSecret string) (refreshTokenStr string, err error) {
	refreshTokenExp := time.Now().Add(REFRESH_TOKEN_VALIDATE_TIME).Unix()
	refreshJti := generateAndStoreRefreshTokenJti()

	refreshClaims := TokenClaims{
		jwt.StandardClaims{Id: refreshJti, Subject: userId, ExpiresAt: refreshTokenExp},
		csrfSecret,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenStr, err = refreshJwt.SignedString(signKey)

	return
}

func CreateAuthTokenString(userId, csrfSecret string) (accessTokenStr string, err error) {
	accessTokenExp := time.Now().Add(ACCESS_TOKEN_VALIDATE_TIME).Unix()

	accessClaims := TokenClaims{
		jwt.StandardClaims{ExpiresAt: accessTokenExp, Subject: userId},
		csrfSecret,
	}

	accessToken := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), accessClaims)
	accessTokenStr, err = accessToken.SignedString(signKey)

	return
}

func NillifyTokenCookies(ctx *gin.Context) {
	expireAt := time.Now().Add(-1000 * time.Hour)
	maxAge := int(time.Since(expireAt).Seconds()) // Calculate maxAge as the number of seconds since expireAt

	ctx.SetCookie("AccessToken", "", maxAge, "", "", true, true)
	ctx.SetCookie("RefreshToken", "", maxAge, "", "", true, true)
}

func SetCookies(ctx *gin.Context, accessToken, refreshToken string) {
	ctx.SetCookie("AccessToken", accessToken, 0, "", "", true, true)
	ctx.SetCookie("RefreshToken", refreshToken, 0, "", "", true, true)
}

func generateAndStoreRefreshTokenJti() string {
	jti := utils.GenerateRandomString(64)
	database.Set(jti, "valid")

	return jti
}
