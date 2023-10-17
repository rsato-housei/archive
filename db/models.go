package db

import "gorm.io/gorm"


type User struct {
	gorm.Model
	Email    string `json:"email" validate:"email,required,max=255" form:"email"`
	Name     string `json:"username" validate:"required,max=255" form:"username"`
	Password string `json:"password" validate:"required,max=255" form:"password"`
}