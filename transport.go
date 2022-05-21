package vkoauth

import (
	"context"
	"net/http"
)

var HTTPClient contextKey

type contextKey struct{}

// Возвращает http клиент из контекста, если он там есть
func ContextClient(ctx context.Context) *http.Client {
	if ctx != nil {
		if hc, ok := ctx.Value(HTTPClient).(*http.Client); ok {
			return hc
		}
	}
	return http.DefaultClient
}
