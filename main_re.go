package main

import (
	"encoding/json"
	"time"

	"archive/db"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/middleware/jwt"
)

const (
	accessTokenMaxAge  = 10 * time.Minute
	refreshTokenMaxAge = time.Hour
)

type UserClaims struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var (
	privateKey, publicKey = jwt.MustLoadRSA("secrets/rsa_private_key.pem", "secrets/rsa_public_key.pem")

	signer            = jwt.NewSigner(jwt.RS256, privateKey, accessTokenMaxAge)
	verifier          = jwt.NewVerifier(jwt.RS256, publicKey)
	gormDB            = db.New()
	updateUser        = db.UpdateUserFunc(gormDB)
	readUserFromEmail = db.ReadUserFromEmailFunc(gormDB)
	tokens			  = map[string]string{}
)

func main() {
	app := iris.New()
	app.OnErrorCode(iris.StatusUnauthorized, handleUnauthorized)

	app.Get("/authenticate", generateTokenPair)
	app.Get("/refresh", refreshToken)

	protectedAPI := app.Party("/protected")
	{
		verifyMiddleware := verifier.Verify(func() interface{} {
			return new(UserClaims)
		})

		protectedAPI.Use(verifyMiddleware)

		protectedAPI.Get("/", func(ctx iris.Context) {
			user := ctx.User()
			id, _ := user.GetID()
			username, _ := user.GetUsername()
			ctx.Writef("ID: %s\nUsername: %s\n", id, username)
		})
	}
	app.Listen(":8000")
}

func generateTokenPair(ctx iris.Context) {
	claims := UserClaims{}
	body, _ := ctx.GetBody()
	err := json.Unmarshal(body, &claims)
	if err != nil || claims.Email == "" || claims.Password == "" {
		ctx.StopWithStatus(iris.StatusBadRequest)
		return
	}
	user, success := readUserFromEmail(claims.Email)
	if success != true {
		ctx.Application().Logger().Errorf("read user from email:")
		ctx.StopWithStatus(iris.StatusInternalServerError)
		return
	}
	if user.Email == "" {
		ctx.StopWithStatus(iris.StatusUnauthorized)
		return
	}
	userID := user.Email
	refreshClaims := jwt.Claims{Subject: userID}

	accessClaims := jwt.Claims{Subject: userID}

	tokenPair, err := signer.NewTokenPair(accessClaims, refreshClaims, refreshTokenMaxAge)
	if err != nil {
		ctx.Application().Logger().Errorf("token pair: %v", err)
		ctx.StopWithStatus(iris.StatusInternalServerError)
		return
	}
	tokens[userID] = string(tokenPair.RefreshToken)
	ctx.JSON(tokenPair)
}

func refreshToken(ctx iris.Context) {
	currentUserID := jwt.Get(ctx).(*UserClaims).Email

	refreshToken := []byte(ctx.URLParam("refresh_token"))
	if len(refreshToken) == 0 {
		// You can read the whole body with ctx.GetBody/ReadBody too.
		var tokenPair jwt.TokenPair
		if err := ctx.ReadJSON(&tokenPair); err != nil {
			ctx.StopWithError(iris.StatusBadRequest, err)
			return
		}

		refreshToken = tokenPair.RefreshToken
	}

	// Verify the refresh token, which its subject MUST match the "currentUserID".
	_, err := verifier.VerifyToken(refreshToken, jwt.Expected{Subject: currentUserID})
	if err != nil {
		ctx.Application().Logger().Errorf("verify refresh token: %v", err)
		ctx.StatusCode(iris.StatusUnauthorized)
		return
	}
	generateTokenPair(ctx)
}

func handleUnauthorized(ctx iris.Context) {
	if err := ctx.GetErr(); err != nil {
		ctx.Application().Logger().Errorf("unauthorized: %v", err)
	}

	ctx.WriteString("Unauthorized")
}
