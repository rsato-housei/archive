package main

import (
	"archive/auth"
	"archive/db"

	"github.com/kataras/iris"
	"github.com/kataras/iris/v12/middleware/jwt"
)

func main(){
	db := db.New()
	app := iris.New()
	bearer := jwt.New(jwt.Config{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return auth.Secret, nil
		},
		Expiration: true,
		Extractor:  jwt.FromAuthHeader,
	}).Unless(func(ctx iris.Context) bool {
		return ctx.Path() == "/token" || ctx.Path() == "/authenticate" || ctx.Path() == "/refresh"
	})
	
	generateToken := auth.GenerateTokenFunc(signer)

	// このミドルウェアを登録することで、jwt.Get()で`UserClaim`が使えるようになる
	verifyMiddleware := verifier.Verify(
		func() interface{} { return new(auth.UserClaim) })


	//not protected
	{
		app.Get("/token", generateToken)
		app.Get("/authenticate", auth.GenerateTokenPair)
		app.Get("/refresh", auth.RefreshToken)
	}

	// protected
	protectedAPI := app.Party("/")
	{
		protectedAPI.Use(verifyMiddleware)
		protectedAPI.Get("/", Protected)
		protectedAPI.Get("/logout", Logout)
	}

	app.Listen(":8000")
}