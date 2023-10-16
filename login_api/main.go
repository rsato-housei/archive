package main

import (
	"encoding/hex"
	"os"
	"time"

	mysql_driver "github.com/go-sql-driver/mysql"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/middleware/basicauth"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	db := initDB()
	authenticate := getAuthenticateFunc(db)
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

func getSignupFunc(db *gorm.DB) func(ctx iris.Context) {
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

func getAuthenticateFunc(db *gorm.DB) func(ctx iris.Context, email, password string) (interface{}, bool) {
	return func(ctx iris.Context, email, password string) (interface{}, bool) {
		u := User{}
		result := db.Where("email = ?", email).First(&u)
		println(u.Email, u.Password)
		// Databaseに一致するメールアドレスがない場合
		if result.Error != nil {
			return &u, false
		}
		err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
		// Userのパスワードと一致しなかった場合
		if err != nil {
			println("authenticate:", err)
			return User{}, false
		}
		println("success: ", email, password)
		//認証成功
		return &u, true

	}
}

func initDB() *gorm.DB {
	cfg := mysql_driver.Config{
		DBName:               "mydb",
		User:                 os.Getenv("DBUSER"), // 環境変数に予め設定しておくこと！
		Passwd:               os.Getenv("DBPASS"), // 環境変数に予め設定しておくこと！
		Net:                  "tcp",
		Addr:                 "127.0.0.1:3306", // デフォルトのMySQLポート
		AllowNativePasswords: true,
		ParseTime:            true,
	}
	db, err := gorm.Open(mysql.Open(cfg.FormatDSN()), &gorm.Config{})

	if err != nil {
		println(cfg.FormatDSN())
		panic("データベース接続失敗")
	}
	db.AutoMigrate(&User{})
	return db
}

func emptyPage(ctx iris.Context) {
	println(ctx)
}
