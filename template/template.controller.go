package template

import (
	"net/http"

	"github.com/gin-gonic/gin"
	auth "github.com/golang-programming/csrf-gin-mysql/auth/utils"
)

/* render html templates */
func RegisterPage(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "register.tmpl", gin.H{
		"BAlertUser": false,
		"AlertMsg":   "",
	})
}

func RestrictedPage(ctx *gin.Context) {
	token := auth.GrabCSRFFromContext(ctx)

	ctx.HTML(http.StatusOK, "restricted.tmpl", gin.H{
		"csrfSecret": token,
	})
}

func LoginPage(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "login.tmpl", gin.H{
		"BAlertUser": false,
		"AlertMsg":   "",
	})
}
