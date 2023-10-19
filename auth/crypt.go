package auth

import "golang.org/x/crypto/bcrypt"

type NonAuthenticatedUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u *NonAuthenticatedUser) PasswordEncrypt() (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	return string(hash), err
}

func (u *NonAuthenticatedUser) CompareHashAndPassword(hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(u.Password))
}
