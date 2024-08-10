package auth

import "github.com/gin-gonic/gin"

func RegisterRoutes(router *gin.RouterGroup) {
	routerGroup := router.Group("/auth")
	routerGroup.POST("/login", LoginController)
	routerGroup.POST("/register", RegisterController)
	routerGroup.POST("/logout", LogoutController)
}
