# 使用するgoを指定
FROM golang:1.21.4-alpine3.17

# 作業ディレクトリを指定
WORKDIR /go/src/iris-app

#  アップデートとgitのインストール
RUN apk update && apk add git

# 依存関係のインストール
COPY go.mod go.sum ./
RUN go mod download

# 作業ディレクトリの作成
RUN mkdir /go/src/iris-app


# ホストのファイルをコンテナの作業ディレクトリに移行 ADDコマンドはコピーと同じ
ADD . /go/src/iris-app

# Port
EXPOSE 8080

# パッケージのインポート
# RUN go get -u golang.org/x/tools/cmd/goimports

CMD ["./main"]