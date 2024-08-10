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

func CheckAndRefreshTokens(accessTokenStr, refreshTokenStr, csrfSecret string) (string, string, string, error) {
	accessTokenClaims, err := parseTokenClaims(accessTokenStr)
	if err != nil {
		return "", "", "", err
	}

	if csrfSecret != accessTokenClaims.CSRFSecret {
		return "", "", "", errors.New("unauthorized")
	}

	if time.Now().Unix() < accessTokenClaims.ExpiresAt {
		newRefreshTokenStr, err := updateTokenExp(refreshTokenStr, accessTokenClaims.CSRFSecret)
		if err != nil {
			return "", "", "", err
		}
		return accessTokenStr, newRefreshTokenStr, accessTokenClaims.CSRFSecret, nil
	}

	newAccessTokenStr, newCSRFSecret, err := updateAccessToken(refreshTokenStr)
	if err != nil {
		return "", "", "", err
	}

	newRefreshTokenStr, err := updateTokenExp(refreshTokenStr, newCSRFSecret)
	if err != nil {
		return "", "", "", err
	}

	return newAccessTokenStr, newRefreshTokenStr, newCSRFSecret, nil
}

func CreateTokensService(ctx *gin.Context, userId string) {
	accessTokenStr, refreshTokenStr, csrfSecret, err := createTokensHelper(userId)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	utils.SetCookies(ctx, accessTokenStr, refreshTokenStr)
	ctx.Header("X-CSRF-Token", csrfSecret)
	ctx.JSON(http.StatusOK, gin.H{"success": true})
}

func createTokensHelper(userId string) (string, string, string, error) {
	csrfSecret := utils.GenerateCSRFSecret()

	refreshTokenStr, err := createToken(userId, csrfSecret, REFRESH_TOKEN_VALIDATE_TIME)
	if err != nil {
		return "", "", "", errors.New("error creating refresh token")
	}

	accessTokenStr, err := createToken(userId, csrfSecret, ACCESS_TOKEN_VALIDATE_TIME)
	if err != nil {
		return "", "", "", errors.New("error creating access token")
	}

	return accessTokenStr, refreshTokenStr, csrfSecret, nil
}

func createToken(userId, csrfSecret string, duration time.Duration) (string, error) {
	expirationTime := time.Now().Add(duration).Unix()
	refreshJti := generateAndStoreRefreshTokenJti()

	tokenClaims := TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        refreshJti,
			Subject:   userId,
			ExpiresAt: expirationTime,
		},
		CSRFSecret: csrfSecret,
	}

	return jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims).SignedString(signKey)
}

func updateAccessToken(refreshTokenStr string) (string, string, error) {
	refreshTokenClaims, err := parseTokenClaims(refreshTokenStr)
	if err != nil {
		return "", "", err
	}

	if err = refreshTokenClaims.Valid(); err != nil || !database.Has(refreshTokenClaims.Id) {
		database.Delete(refreshTokenClaims.Id)
		return "", "", errors.New("unauthorized")
	}

	csrfSecret := utils.GenerateCSRFSecret()
	newAccessTokenStr, err := createToken(refreshTokenClaims.Subject, csrfSecret, ACCESS_TOKEN_VALIDATE_TIME)
	return newAccessTokenStr, csrfSecret, err
}

func updateTokenExp(tokenStr, csrfSecret string) (string, error) {
	tokenClaims, err := parseTokenClaims(tokenStr)
	if err != nil {
		return "", err
	}

	if tokenClaims == nil {
		return "", errors.New("invalid token claims")
	}

	tokenClaims.ExpiresAt = time.Now().Add(REFRESH_TOKEN_VALIDATE_TIME).Unix()
	tokenClaims.CSRFSecret = csrfSecret

	return jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims).SignedString(signKey)
}

func parseTokenClaims(tokenStr string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

func generateAndStoreRefreshTokenJti() string {
	jti := commonUtils.GenerateRandomString(64)
	database.Set(jti, "valid")
	return jti
}
