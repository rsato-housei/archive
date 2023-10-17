package db

import (
	"os"

	mysql_driver "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func New() *gorm.DB {
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

func UpdateUserFunc(db *gorm.DB) func(u User) {
	return func(u User) {
		// ユーザー情報を更新する関数
		db.Save(&u)
	}
}

func ReadUserFromEmailFunc(db *gorm.DB) func(email string) (*User, bool) {
	// メールアドレスからユーザーを取得する関数を返す
	return func(email string) (*User, bool) {
		u := User{}
		result := db.Where("email = ?", email).First(&u)
		println(u.Email, u.Password)
		// Databaseに一致するメールアドレスがない場合, エラーの場合
		if result.Error != nil || u.Email == "" {
			return &u, false
		}
		return &u, true

	}
}
