package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/navikt/story-api/pkg/api"
)

func main() {
	var bucketName string
	var clientID string
	var clientSecret string
	var tenantID string
	var hmacKey string
	var host string
	flag.StringVar(&bucketName, "bucket", os.Getenv("STORY_BUCKET"), "The storage bucket for the story content")
	flag.StringVar(&clientID, "client-id", os.Getenv("CLIENT_ID"), "The azure app client id")
	flag.StringVar(&clientSecret, "client-secret", os.Getenv("CLIENT_SECRET"), "The azure app client secret")
	flag.StringVar(&tenantID, "tenant-id", os.Getenv("TENANT_ID"), "The tenant ID")
	flag.StringVar(&hmacKey, "hmac-key", os.Getenv("HMAC_KEY"), "The tenant ID")
	flag.StringVar(&host, "host", "https://quarto-previewer.dev.knada.io", "The tenant ID")
	flag.Parse()

	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	router, err := api.New(ctx, bucketName, clientID, clientSecret, tenantID, host, hmacKey, logger.With("subsystem", "api"))
	if err != nil {
		logger.Error("creating api", "error", err)
		os.Exit(1)
	}

	server := http.Server{
		Addr:    ":8080",
		Handler: router.Router,
	}

	if err := server.ListenAndServe(); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
