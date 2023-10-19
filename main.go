package main

import (
	"archive/auth"
	"archive/database"
	"fmt"

	"github.com/kataras/iris/v12"
)

func main() {
	app := iris.New()
	app.OnErrorCode(iris.StatusUnauthorized, handleUnauthorized)
	app.Post("/signup", signup)
	app.Post("/login", login)
	database.InitDB()

	protectedAPI := app.Party("/protected")
	{

		protectedAPI.Use(auth.GetVerifyMiddleware())

		protectedAPI.Get("/", func(ctx iris.Context) {
			user := ctx.User()
			id, _ := user.GetID()
			username, _ := user.GetUsername()
			ctx.Writef("ID: %s\nUsername: %s\n", id, username)
		})
	}
	app.Listen(":8000")
}

func handleUnauthorized(ctx iris.Context) {
	if err := ctx.GetErr(); err != nil {
		ctx.Application().Logger().Errorf("unauthorized: %v", err)
	}

	ctx.WriteString("Unauthorized")
}

func signup(ctx iris.Context) {
	user := database.User{}
	err := ctx.ReadJSON(&user)
	if err != nil {
		ctx.StopWithStatus(iris.StatusBadRequest)
		ctx.WriteString(err.Error())
		return
	}
	if !user.CheckRequired() {
		ctx.StopWithStatus(iris.StatusBadRequest)
		ctx.WriteString(fmt.Sprintf("required: %v", user))
		return
	}
	non_user := auth.NonAuthenticatedUser{
		Email:    user.Email,
		Password: user.Password,
	}
	user.Password, err = non_user.PasswordEncrypt()
	if err != nil {
		ctx.StopWithStatus(iris.StatusInternalServerError)
		ctx.WriteString(err.Error())
		return
	}
	err = user.Create()
	if err != nil {
		ctx.StopWithStatus(iris.StatusInternalServerError)
		ctx.WriteString(err.Error())
		return
	}
	ctx.StatusCode(iris.StatusOK)
}

func login(ctx iris.Context) {
	non_user := auth.NonAuthenticatedUser{}
	err := ctx.ReadJSON(&non_user)
	if err != nil {
		ctx.StopWithStatus(iris.StatusBadRequest)
		return
	}
	user := database.User{}
	err = user.FindByEmail(non_user.Email)
	if err != nil || non_user.CompareHashAndPassword(user.Password) != nil {
		ctx.StopWithStatus(iris.StatusBadRequest)
		return
	}
	auth.GenerateTokenPair(ctx, user.Email)
}
