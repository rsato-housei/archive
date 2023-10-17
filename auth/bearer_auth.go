package auth

import (
	"encoding/json"
	"os"
	"time"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/middleware/jwt"
	"gorm.io/gorm"
)

var (
	secret       = []byte(os.Getenv("SECRET_KEY")) // TODO: export SECRET_KEY
	useAlgorithm = jwt.HS256
	maxAge       = 10 * time.Minute
	logger       = iris.Default().Logger().Print
)

type UserClaims struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func GenerateTokenFunc(signer *jwt.Signer) iris.Handler {
	return func(ctx iris.Context) {
		claims := UserClaim{}
		body, _ := ctx.GetBody()
		logger(claims.Email, claims.Password)
		err := json.Unmarshal(body, &claims)

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
}

func Protected(ctx iris.Context) {
	verifiedToken := jwt.GetVerifiedToken(ctx)
	standardClaims := verifiedToken.StandardClaims
	expiresAtString := standardClaims.ExpiresAt().
		Format(ctx.Application().ConfigurationReadOnly().GetTimeFormat())
	timeLeft := standardClaims.Timeleft()

	ctx.Writef("claims=%s\nexpires at: %s\ntime left: %s\n", verifiedToken, expiresAtString, timeLeft)
}

func Logout(ctx iris.Context) {
	err := ctx.Logout()
	if err != nil {
		ctx.WriteString(err.Error())
	} else {
		ctx.Writef("token invalidated, a new token is required to access the protected API")
	}
}

func authorize(ctx iris.Context) {
	claims := jwt.Get(ctx).(*UserClaim)
}

func GenerateTokenPair(ctx iris.Context) (string, string) {
	return "", ""
}

func RefreshToken(ctx iris.Context) {

}
func GetAuthenticateFunc() func(ctx iris.Context, email, password string) (interface{}, bool) {
	return func(ctx iris.Context, email, password string) (interface{}, bool) {
		u := db.User{}
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

type BearerToken struct {
	secret []byte
	useAlgorithm jwt.Alg
	maxAge time.Duration
	signer *jwt.Signer
	verifier *jwt.Verifier
}

// BearerTokenのコンストラクタ
func NewBearerToken(secret []byte, useAlgorithm jwt.Alg, maxAge time.Duration) *BearerToken {
	signer := jwt.NewSigner(useAlgorithm, secret, maxAge)
	verifier := jwt.NewVerifier(useAlgorithm, secret)
	return &BearerToken{
		secret: secret,
		useAlgorithm: useAlgorithm,
		maxAge: maxAge,
		signer: signer,
		verifier: verifier,
	}
}


// UserClaimsからアクセストークンとリフレッシュトークンを生成するメソッド
func (b *BearerToken) GenerateTokenPair(claims UserClaims) ([]byte, []byte) {
	accessToken, _ := b.signer.Sign(claims)
	refreshToken, _ := b.signer.Sign(claims)
	return accessToken, refreshToken
}

// アクセストークンを検証するメソッド
func (b *BearerToken) VerifyAccessToken(accessToken []byte)

func (b *BearerToken) GetVerifyMiddleware() iris.Handler {
	return b.verifier.Verify(func() interface{} { return new(UserClaim) })
}