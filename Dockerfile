# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o bin/ticketradar ./cmd/server

# Runtime stage — imagem mínima
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app

COPY --from=builder /app/bin/ticketradar .
COPY --from=builder /app/web ./web

# Criar usuário não-root e diretório /data com permissões corretas
RUN addgroup -S ticketradar && adduser -S ticketradar -G ticketradar && \
    mkdir -p /data && chown ticketradar:ticketradar /data

USER ticketradar

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["./ticketradar"]
