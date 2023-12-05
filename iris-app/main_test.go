package iris_app

import (
    "github.com/kataras/iris/v12"
    "github.com/kataras/iris/v12/httptest"
    "testing"
)

func TestMainFunction(t *testing.T) {
    app := iris.New()

    app.Handle("GET", "/", func(ctx iris.Context) {
        ctx.JSON(iris.Map{"message": "ping"})
    })

    testApp := httptest.New(t, app)

    resp := testApp.GET("/").Expect().Status(httptest.StatusOK).JSON().Object()

    resp.Value("message").Equal("ping")
}