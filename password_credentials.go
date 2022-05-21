package vkoauth

import (
	"context"
	"strconv"
)

type TokenParams struct {
	TestRedirectUri bool   // Использовать ли тестовую проверку
	TwoFaSupported  bool   // Ваше приложение поддерживает двухфакторную аутентификацию
	Username        string // Логин пользователя
	Password        string // Пароль пользователя
	Code            string // Код для прохождения двухфакторной аутентификации
	CaptchaSid      string // Идентификатор полученной капчи
	CaptchaKey      string // Код с картинки, полученной капчи
}

// Получает токен по логину и паролю пользователя
// Возвращает ошибку *TokenError, если возникла ошибка авторизации
func (v *Config) PasswordCredentials(ctx context.Context, p TokenParams, opts ...AuthOption) (*Token, error) {

	tokenOpts := []AuthOption{
		setParam{"grant_type", "password"},
		setParam{"username", p.Username},
		setParam{"password", p.Password},
	}

	if v.Scope != 0 {
		tokenOpts = append(tokenOpts, setParam{"scope", strconv.FormatInt(int64(v.Scope), 10)})
	}

	if p.TestRedirectUri {
		tokenOpts = append(tokenOpts, setParam{"test_redirect_uri", "1"})
	}

	if p.CaptchaKey != "" {
		tokenOpts = append(tokenOpts, setParam{"captcha_key", p.CaptchaKey})
		tokenOpts = append(tokenOpts, setParam{"captcha_sid", p.CaptchaSid})
	}

	if p.Code != "" {
		tokenOpts = append(tokenOpts, setParam{"code", p.Code})
	}

	if p.TwoFaSupported {
		tokenOpts = append(tokenOpts, setParam{"2fa_supported", "1"})
	}

	tokenOpts = append(tokenOpts, opts...)
	return v.doTokenRequest(ctx, v.buildTokenUrl(v.endpoint().PasswordTokenUrl,
		tokenOpts...,
	))
}
