package auth

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/golang-programming/csrf-gin-mysql/auth/utils"
	"github.com/golang-programming/csrf-gin-mysql/database"
	commonUtils "github.com/golang-programming/csrf-gin-mysql/utils"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func CheckAndRefreshTokens(accessTokenStr, refreshTokenStr, csrfSecret string) (newAccessTokenStr, newRefreshTokenStr, newCSRFSecret string, err error) {
	//

	accessToken, err := jwt.ParseWithClaims(accessTokenStr, &TokenClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	accessTokenClaims, ok := accessToken.Claims.(*TokenClaims)
	if !ok {
		return
	}

	if csrfSecret != accessTokenClaims.CSRFSecret {
		err = errors.New("Unauthorized")
		return
	}

	if accessToken.Valid {
		newCSRFSecret = accessTokenClaims.CSRFSecret
		newAccessTokenStr = accessTokenStr
		newRefreshTokenStr, err = updateRefreshTokenExp(refreshTokenStr)

		return
	}

	if accessTokenClaims.StandardClaims.ExpiresAt < time.Now().Unix() {
		newAccessTokenStr, newCSRFSecret, err = updateAccessTokenStr(refreshTokenStr, accessTokenStr)
		if err != nil {
			return
		}

		newRefreshTokenStr, err = updateRefreshTokenExp(refreshTokenStr)
		if err != nil {
			return
		}

		newRefreshTokenStr, err = updateRefreshTokenCsrf(newAccessTokenStr, newCSRFSecret)
		return
	}

	err = errors.New("Error in auth token")
	return
}

func updateRefreshTokenCsrf(refreshTokenStr string, newCsrfString string) (newRefreshTokenStr string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenStr, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*TokenClaims)
	if !ok {
		return
	}

	refreshClaims := TokenClaims{
		jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.StandardClaims.ExpiresAt,
		},
		newCsrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenStr, err = refreshJwt.SignedString(signKey)
	return
}

func CreateTokensService(ctx *gin.Context, userId string) {
	authTokenStr, refreshTokenStr, csrfSecret, err := createTokensHelper(userId)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	utils.SetCookies(ctx, authTokenStr, refreshTokenStr)
	ctx.Header("X-CSRF-Token", csrfSecret)

	ctx.JSON(http.StatusOK, gin.H{"success": true})
}

func createTokensHelper(userId string) (accessToken, refreshToken, csrfSecret string, err error) {
	csrfSecret = utils.GenerateCSRFSecret()

	refreshToken, _ = createRefreshTokenStr(userId, csrfSecret)
	accessToken, err = createAccessTokenStr(userId, csrfSecret)

	if err != nil {
		err = errors.New("error: creating tokens")
	}

	return
}

func createRefreshTokenStr(userId, csrfSecret string) (refreshTokenStr string, err error) {
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

func createAccessTokenStr(userId, csrfSecret string) (accessTokenStr string, err error) {
	accessTokenExp := time.Now().Add(ACCESS_TOKEN_VALIDATE_TIME).Unix()

	accessClaims := TokenClaims{
		jwt.StandardClaims{ExpiresAt: accessTokenExp, Subject: userId},
		csrfSecret,
	}

	accessToken := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), accessClaims)
	accessTokenStr, err = accessToken.SignedString(signKey)

	return
}

func updateRefreshTokenExp(refreshTokenStr string) (newRefreshTokenStr string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenStr, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	refreshTokenClaims, ok := refreshToken.Claims.(*TokenClaims)
	if !ok {
		return
	}

	refreshTokenExp := time.Now().Add(REFRESH_TOKEN_VALIDATE_TIME).Unix()

	refreshClaims := TokenClaims{
		jwt.StandardClaims{

			Id:        refreshTokenClaims.StandardClaims.Id, // jti
			Subject:   refreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: refreshTokenExp,
		},
		refreshTokenClaims.CSRFSecret,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	newRefreshTokenStr, err = refreshJwt.SignedString(signKey)

	return
}

func updateAccessTokenStr(refreshTokenStr, accessTokenStr string) (newAccessTokenStr, csrfSecret string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenStr, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	refreshTokenClaims, ok := refreshToken.Claims.(*TokenClaims)
	if !ok {
		return
	}

	if database.Has(refreshTokenClaims.StandardClaims.Id) {
		if refreshToken.Valid {
			accessToken, _ := jwt.ParseWithClaims(accessTokenStr, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})

			accessTokenClaims, ok := accessToken.Claims.(*TokenClaims)

			if !ok {
				err = errors.New("Unexpected token error")
			}

			csrfSecret = utils.GenerateCSRFSecret()
			newAccessTokenStr, err = createAccessTokenStr(accessTokenClaims.StandardClaims.Subject, csrfSecret)

			return
		}

		database.Delete(refreshTokenClaims.StandardClaims.Id)
		err = errors.New("Unauthorized")
		return
	}

	err = errors.New("Unauthorized")
	return
}

func generateAndStoreRefreshTokenJti() string {
	jti := commonUtils.GenerateRandomString(64)
	database.Set(jti, "valid")

	return jti
}
