package main

import (
	"os"

	"github.com/gin-gonic/gin"
	auth "github.com/golang-programming/csrf-gin-mysql/auth"
	"github.com/golang-programming/csrf-gin-mysql/database"
	template "github.com/golang-programming/csrf-gin-mysql/template"
)

func main() {
	LoadEnv()
	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	router := gin.New()
	router.LoadHTMLGlob("template/templateFiles/*")

	// register routes
	routerGroup := router.Group("/api")
	auth.RegisterRoutes(routerGroup)
	template.RegisterRoutes(router)

	database.ConnectToDatabase()
	database.InitializeRedis()
	router.Run(":" + port)
}
