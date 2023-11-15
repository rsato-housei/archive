package database

import (
	"fmt"
	"os"

	mysql_driver "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var d *gorm.DB

func InitDB() {
	cfg := mysql_driver.Config{
		DBName:               "mydb",
		User:                 os.Getenv("DBUSER"), // 環境変数に予め設定しておくこと！
		Passwd:               os.Getenv("DBPASS"), // 環境変数に予め設定しておくこと！
		Net:                  "tcp",
		Addr:                 "127.0.0.1:3306", // デフォルトのMySQLポート
		AllowNativePasswords: true,
		ParseTime:            true,
	}
	var err error
	d, err = gorm.Open(mysql.Open(cfg.FormatDSN()), &gorm.Config{})

	if err != nil {
		fmt.Println(err)
		panic("データベース接続失敗")
	}
	d.AutoMigrate(User{})
}

// GetDB returns database connection
func GetDB() *gorm.DB {
	return d
}