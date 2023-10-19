package auth

import (
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/middleware/jwt"
)

const (
	accessTokenMaxAge  = 10 * time.Minute
	refreshTokenMaxAge = time.Hour
)

var (
	secret                = []byte(os.Getenv("SECRET_KEY")) // TODO: export SECRET_KEY
	useAlgorithm          = jwt.HS256
	maxAge                = 10 * time.Minute
	logger                = iris.Default().Logger().Print
	privateKey, publicKey = jwt.MustLoadRSA("secrets/rsa_private_key.pem", "secrets/rsa_public_key.pem")

	signer           = jwt.NewSigner(jwt.RS256, privateKey, accessTokenMaxAge)
	verifier         = jwt.NewVerifier(jwt.RS256, publicKey)
	verifyMiddleware = verifier.Verify(func() interface{} {
		return new(UserClaim)
	})
	refreshTokens = map[string]string{} // Email: RefreshToken
)

type UserClaim struct {
	Email string `json:"email"`
	UUID  string `json:"uuid"`
}

func GenerateNewRefreshToken(ctx iris.Context) {
	claims := UserClaim{}
	err := ctx.ReadJSON(&claims)

	if err != nil {
		logger("generateTokenFunc:", err)
	}
	token, err := signer.Sign(claims)
	if err != nil {
		ctx.StopWithStatus(iris.StatusInternalServerError)
		return
	}
	ctx.Write(token)
}

func Protected(ctx iris.Context) {
	verifiedToken := jwt.GetVerifiedToken(ctx)// .(*UserClaim)
	standardClaims := verifiedToken.StandardClaims
	expiresAtString := standardClaims.ExpiresAt().
		Format(ctx.Application().ConfigurationReadOnly().GetTimeFormat())
	timeLeft := standardClaims.Timeleft()

	ctx.Writef("claims=%s\nexpires at: %s\ntime left: %s\n", standardClaims.Subject, expiresAtString, timeLeft)
}

func Logout(ctx iris.Context) {
	err := ctx.Logout()
	if err != nil {
		ctx.WriteString(err.Error())
	} else {
		ctx.Writef("token invalidated, a new token is required to access the protected API")
	}
}

func GenerateTokenPair(ctx iris.Context, email string) {
	claim := UserClaim{
		Email: email,
		UUID:  uuid.New().String(),
	}
	tokenPair, err := signer.NewTokenPair(claim, claim, refreshTokenMaxAge)
	if err != nil {
		logger("token pair:", err)
		ctx.StopWithStatus(iris.StatusInternalServerError)
	}
	refreshTokens[email] = string(tokenPair.RefreshToken)
	ctx.JSON(tokenPair)
}

func GetVerifyMiddleware() iris.Handler {
	return verifyMiddleware
}