package utils

import "encoding/base64"

func GenerateRandomString(n int) string {
	bytes := GenerateRandomBytes(n)
	return base64.URLEncoding.EncodeToString(bytes)
}
