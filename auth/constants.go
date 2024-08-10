package auth

import "time"

const REFRESH_TOKEN_VALIDATE_TIME = time.Hour * 72
const ACCESS_TOKEN_VALIDATE_TIME = time.Hour * 6
