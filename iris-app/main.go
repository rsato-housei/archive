package main

import "github.com/kataras/iris/v12"

func main() {
    app := iris.New()

    app.Handle("GET", "/", func(ctx iris.Context) {
        ctx.JSON(iris.Map{"message": "ping"})
    })
	
    app.Listen(":8080")
}