# 使用するgoを指定
# Base Image

FROM golang:1.21.4-alpine AS builder

# 作業ディレクトリの作成
# RUN mkdir /go/src/iris-app

# 作業ディレクトリを指定
WORKDIR /go/src/iris-app



# 依存関係のインストール
COPY /go.mod .
COPY /go.sum .
RUN go mod download


# ホストのファイルをコンテナの作業ディレクトリに移行 ADDコマンドはコピーと同じ
COPY /main.go . 

# ビルド
RUN go build -o main . # -oは、出力ファイル名を指定するオプション


# 本番用のイメージを作成
FROM gcr.io/distroless/static-debian11:latest AS production

WORKDIR /

COPY --from=builder /go/src/iris-app/main .

USER nonroot


ENTRYPOINT ["/main"]

# Port
EXPOSE 8080

# NOTICE
# Dockerのビルドキャッシュは、各ステップごとにキャッシュされます。
# go.modとgo.sumを最初にコピーすることで、これらのファイルが変更されない限り、
# Dockerはこのステップをキャッシュから再利用します。
# これにより、依存関係が変更されていない場合には不必要に再ダウンロードされることがなくなり、
# ビルドが高速化されます。

# 一般的なDockerfileのパフォーマンス最適化の手順として、
# 頻繁に変更される部分と変更されない部分を分け、変更されない部分を先に配置して
# ビルドキャッシュの有効な活用を図ることがあります。