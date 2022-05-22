package vkoauth_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/ciricc/vkoauth"
)

func TestContextClient(t *testing.T) {
	ctx := context.WithValue(context.Background(), vkoauth.HTTPClient, nil)
	if vkoauth.ContextClient(ctx) == nil {
		t.Errorf("unexpected client: %v", vkoauth.ContextClient(ctx))
	}
	if vkoauth.ContextClient(ctx) != http.DefaultClient {
		t.Errorf("unexpected client: %v", ctx)
	}
}

func TestContextClientNonNil(t *testing.T) {
	c := http.Client{}
	ctx := context.WithValue(context.Background(), vkoauth.HTTPClient, &c)
	if vkoauth.ContextClient(ctx) != &c {
		t.Errorf("unexpected client: %v", vkoauth.ContextClient(ctx))
	}
}

func TestContextClientInvalidType(t *testing.T) {
	c := http.Client{}
	ctx := context.WithValue(context.Background(), vkoauth.HTTPClient, c)
	if vkoauth.ContextClient(ctx) != http.DefaultClient {
		t.Errorf("unexpected client: %v", vkoauth.ContextClient(ctx))
	}
}
