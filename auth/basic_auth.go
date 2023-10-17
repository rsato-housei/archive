package auth

import (
	"encoding/hex"
	"time"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/middleware/basicauth"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)




func main() {
	db := InitDB()
	authenticate := GetAuthenticateFunc(db)
	signup := getSignupFunc(db)

	app := iris.New()
	// authentication
	opts := basicauth.Options{
		Realm:        "Authorization Required",
		ErrorHandler: basicauth.DefaultErrorHandler,
		MaxTries:     5,
		GC: basicauth.GC{
			Every: 30 * time.Minute,
		},
		Allow: authenticate,
	}
	auth := basicauth.New(opts)

	app.Post("/signup", signup) // 認証なしでアクセス可能
	loginAPI := app.Party("/")
	{
		loginAPI.Use(iris.Compression) // メッセージを圧縮、解凍するミドルウェア
		loginAPI.Use(auth)             // 認証を行うミドルウェア
		loginAPI.Get("/", emptyPage)
		loginAPI.Post("/logout", logout)
	}
	app.Listen("localhost:8000")
}

func GetSignupFunc(db *gorm.DB) func(ctx iris.Context) {
	return func(ctx iris.Context) {
		u := User{}
		err := ctx.ReadForm(&u)

		// Validate form
		if err != nil || u.Name == "" || u.Email == "" || u.Password == "" {
			println("error: signup:", err)
			ctx.StatusCode(iris.StatusBadRequest)
			return
		}
		encrypted, _ := bcrypt.GenerateFromPassword([]byte(u.Password), 4)
		u.Password = hex.EncodeToString(encrypted)

		// TODO: databaseに登録する
		result := db.Create(&u)
		if result.Error != nil {
			println("error: signup: ", result.Error)
			ctx.StatusCode(iris.StatusBadRequest)
			return
		}
	}
}

func logout(ctx iris.Context) {
	err := ctx.Logout()
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		return
	}
	ctx.StatusCode(iris.StatusOK)
}
func emptyPage(ctx iris.Context) {

}