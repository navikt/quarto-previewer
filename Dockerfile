FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY go.sum go.sum
COPY go.mod go.mod
RUN go mod download

COPY main.go main.go
COPY pkg pkg

RUN go build -o quarto-previewer

FROM alpine:3
WORKDIR /app

COPY --from=builder /src/quarto-previewer /app/quarto-previewer

CMD ["/app/quarto-previewer"]