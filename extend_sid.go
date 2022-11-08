package vkoauth

import (
	"context"
	"strconv"
)

type SidParams struct {
	CaptchaKey string // Код от капчи
	CaptchaSid string // Идентификатор капчи
	Sid        string // SID полученный из промежуточного результата авторизации (регистрации)
	Hash       string // Хеш полученный из промежуточного результата авторизации (регистрации)
}

// Получает токен по промежуточным результатам авторизации (регистрации) аккаунта
func (v *Config) ExtendSid(ctx context.Context, p SidParams, opts ...AuthOption) (*Token, error) {
	tokenOpts := []AuthOption{
		setParam{"grant_type", "extend_sid"},
	}

	if v.Scope != 0 {
		tokenOpts = append(tokenOpts, setParam{"scope", strconv.FormatInt(int64(v.Scope), 10)})
	}

	if p.CaptchaKey != "" {
		tokenOpts = append(tokenOpts, setParam{"captcha_key", p.CaptchaKey})
		tokenOpts = append(tokenOpts, setParam{"captcha_sid", p.CaptchaSid})
	}
	
	tokenOpts = append(tokenOpts, setParam{"sid", p.Sid})
	tokenOpts = append(tokenOpts, setParam{"hash", p.Hash})
	
	tokenOpts = append(tokenOpts, opts...)
	return v.doTokenRequest(ctx, v.buildTokenUrl(v.endpoint().PasswordTokenUrl,
		tokenOpts...,
	))
}
