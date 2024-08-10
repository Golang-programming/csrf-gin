package auth

import "github.com/golang-jwt/jwt"

type RegisterInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type TokenClaims struct {
	jwt.StandardClaims
	CSRFSecret string `json:"csrfSecret"`
}
