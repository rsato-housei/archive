# 使用するgoを指定
FROM golang:1.21.4-alpine3.17

#  アップデートとgitのインストール
RUN apk update && apk add git

# 作業ディレクトリの作成
RUN mkdir /go/src/iris-app

# 作業ディレクトリを指定
WORKDIR /go/src/iris-app

# ホストのファイルをコンテナの作業ディレクトリに移行 ADDコマンドはコピーと同じ
ADD . /go/src/iris-app


# パッケージのインポート
RUN go get -u golang.org/x/tools/cmd/goimports