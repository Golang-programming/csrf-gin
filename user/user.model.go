package user

type Role string

const (
	Admin  Role = "admin"
	Client Role = "client"
	Guest  Role = "guest"
)

type User struct {
	// gorm.Model
	// ID       string `gorm:"type:varchar(255);primary_key;" json:"id"`
	ID       string `gorm:"type:type:varchar(255); primary_key;"`
	Username string `gorm:"type:varchar(255); NOT NULL; UNIQUE" json:"username"`
	Password string `gorm:"type:varchar(255); NOT NULL" json:"password"`
}
