package vkoauth

import (
	"context"
)

// Возвращает сервисный ключ доступа по указанным ClientId и ClientSecret
func (v *Config) GetServiceToken(ctx context.Context, opts ...AuthOption) (*Token, error) {
	credentialsOptions := []AuthOption{
		setParam{"grant_type", "client_credentials"},
	}

	credentialsOptions = append(credentialsOptions, opts...)
	return v.doTokenRequest(ctx, v.buildTokenUrl(v.endpoint().TokenUrl,
		credentialsOptions...,
	))
}
