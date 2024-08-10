package auth

import (
	DB "github.com/golang-programming/csrf-gin-mysql/database"
	"github.com/golang-programming/csrf-gin-mysql/user"
)

func GetUserByUsername(username string) (*user.User, error) {
	var user user.User

	result := DB.DB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}
