package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/navikt/story-api/pkg/auth"
	storageClient "github.com/navikt/story-api/pkg/gcs"
)

type API struct {
	Router    *chi.Mux
	gcsClient *storageClient.Client
	bucket    string
	authAPI   HTTP
	logger    *slog.Logger
}

func New(ctx context.Context, bucket, clientID, clientSecret, tenantID, host, hmacKey string, logger *slog.Logger) (*API, error) {
	gcs, err := storageClient.New(ctx, bucket, "", false)
	if err != nil {
		return nil, err
	}

	r := chi.NewRouter()

	aauth := auth.NewAzure(
		clientID,
		clientSecret,
		tenantID,
		fmt.Sprintf("%s/callback", host),
	)

	authAPI := NewHTTP(
		aauth,
		aauth.RedirectURL,
		host+"/",
		hmacKey,
		logger,
	)

	api := &API{
		Router:    r,
		gcsClient: gcs,
		bucket:    bucket,
		authAPI:   authAPI,
		logger:    logger,
	}

	api.setupRoutes(r, gcs, bucket, logger)

	return api, nil
}

func (a *API) setupRoutes(r *chi.Mux, gcs *storageClient.Client, bucket string, logger *slog.Logger) {
	r.With(a.authMiddleware).Get("/*", func(w http.ResponseWriter, r *http.Request) {
		path := chi.URLParam(r, "*")
		if isFile(path) {
			a.GetObject(gcs, bucket).ServeHTTP(w, r)
		} else {
			a.GetIndexHTML(gcs, bucket).ServeHTTP(w, r)
		}
	})

	r.Get("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("healthy"))
	})

	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		a.authAPI.Login(w, r)
	})

	r.Get("/callback", func(w http.ResponseWriter, r *http.Request) {
		a.authAPI.Callback(w, r)
	})
}

func (a *API) GetObject(gcs *storageClient.Client, bucket string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		objPath := fmt.Sprintf("%s/%s", chi.URLParam(r, "id"), chi.URLParam(r, "*"))
		obj, err := gcs.GetObjectWithData(r.Context(), bucket, strings.TrimPrefix(objPath, "/"))
		if err != nil {
			return
		}

		var contentType string

		switch filepath.Ext(obj.Name) {
		case ".html":
			contentType = "text/html"
		case ".js":
			contentType = "text/javascript"
		case ".css":
			contentType = "text/css"
		default:
			contentType = obj.Attrs.ContentType
		}

		w.Header().Add("Content-Type", contentType)
		w.Write(obj.Data)
	})
}

func (a *API) GetIndexHTML(gcs *storageClient.Client, bucket string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		objPath := fmt.Sprintf("%s/%s", chi.URLParam(r, "id"), chi.URLParam(r, "*"))
		objects, err := gcs.GetObjects(r.Context(), bucket, &storageClient.Query{
			Prefix: strings.TrimPrefix(objPath, "/"),
		})
		if err != nil {
			a.logger.Error(fmt.Sprintf("getting objects for story with ID %v", objPath), "error", err)
			return
		}

		sort.Slice(objects, func(i, j int) bool {
			return len(objects[i].Name) < len(objects[j].Name)
		})

		var candidates []string
		for _, obj := range objects {
			if strings.HasSuffix(strings.ToLower(obj.Name), "/index.html") {
				candidates = append(candidates, obj.Name)
				break
			} else if strings.HasSuffix(strings.ToLower(obj.Name), ".html") {
				candidates = append(candidates, obj.Name)
			}
		}

		r.URL.Path = "/"
		http.Redirect(w, r, candidates[0], http.StatusSeeOther)
	})
}

func isFile(path string) bool {
	pathParts := strings.Split(path, "/")
	return strings.Contains(pathParts[len(pathParts)-1], ".")
}
