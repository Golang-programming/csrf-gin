package auth

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/golang-programming/csrf-gin-mysql/auth/utils"
	DB "github.com/golang-programming/csrf-gin-mysql/database"
	"github.com/golang-programming/csrf-gin-mysql/template"
	"github.com/golang-programming/csrf-gin-mysql/user"
	"github.com/google/uuid"
)

func RegisterService(input *RegisterInput) (string, error) {

	existingUser, _ := GetUserByUsername(input.Username)
	if existingUser != nil {
		return "", errors.New("user already registered")
	}

	user := user.User{ID: uuid.New().String(), Username: input.Username, Password: input.Password}
	result := DB.DB.Create(&user)
	if result.Error != nil {
		return "", result.Error
	}

	return user.ID, nil
}

func UserService(input *LoginInput) (string, error) {
	existingUser, _ := GetUserByUsername(input.Username)
	if existingUser == nil {
		return "", errors.New("invalid credentials")
	}

	if err := utils.CheckPasswordHash(input.Password, existingUser.Password); err != nil {
		return "", errors.New("invalid credentials")
	}

	return existingUser.ID, nil
}

func LogoutService(ctx *gin.Context) {
	utils.NillifyTokenCookies(ctx)
	navigateToLoginPage(ctx)
}

func navigateToLoginPage(ctx *gin.Context) {
	template.LoginPage(ctx)
}
