package database

import (
	"log"

	"github.com/golang-programming/csrf-gin-mysql/user"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectToDatabase() {

	dsn := "root:password@tcp(127.0.0.1:3307)/csrf_golang?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatalf("Could not connect to database: %v", err)
	}

	DB = db

	DB.AutoMigrate(&user.User{})
}
