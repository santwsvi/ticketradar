# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o bin/ticketradar ./cmd/server

# Runtime stage — imagem mínima
FROM alpine:3.19

# su-exec: troca de usuário sem fork (como gosu, mas menor)
RUN apk --no-cache add ca-certificates tzdata su-exec

WORKDIR /app

COPY --from=builder /app/bin/ticketradar .
COPY --from=builder /app/web ./web
COPY docker-entrypoint.sh /docker-entrypoint.sh

# Criar usuário não-root para a aplicação
RUN addgroup -S ticketradar && adduser -S ticketradar -G tickeradar -G ticketradar && \
    chmod +x /docker-entrypoint.sh

# Entrypoint roda como root para ajustar permissões do volume,
# depois troca para ticketradar via su-exec
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=5 \
  CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
