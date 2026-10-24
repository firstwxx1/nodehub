# ---- build ----
FROM golang:1.24-alpine AS build
RUN apk add --no-cache bash coreutils
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG SINGBOX_VERSION=1.12.12
RUN SINGBOX_VERSION=$SINGBOX_VERSION OUT=/out ./scripts/build.sh

# ---- runtime ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
ARG TARGETARCH=amd64
COPY --from=build /out/nodehub-linux-${TARGETARCH} /app/nodehub
COPY --from=build /out/dist /app/dist
ENV NODEHUB_DATA=/data \
    NODEHUB_DIST=/app/dist \
    NODEHUB_LISTEN=:8080 \
    TZ=Asia/Shanghai
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/nodehub"]
