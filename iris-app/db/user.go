package database

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Email    string `json:"email" validate:"email,required,max=255" form:"email"`
	Name     string `json:"username" validate:"required,max=255" form:"username"`
	Password string `json:"password" validate:"required,max=255" form:"password"`
}

func (u *User) Create() (err error) {
	db := GetDB()
	res := db.Create(u)
	return res.Error
}

func (u *User) FindByEmail(email string) (err error) {
	db := GetDB()
	return db.Where("email = ?", email).First(u).Error
}

func (u *User) CheckRequired() bool {
	return u.Email != "" && u.Password != "" && u.Name != ""
}
