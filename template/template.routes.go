package template

import "github.com/gin-gonic/gin"

func RegisterRoutes(router *gin.Engine) {
	router.GET("/register", RegisterPage)
	router.GET("/login", LoginPage)
	router.GET("/restricted", RestrictedPage)
}
