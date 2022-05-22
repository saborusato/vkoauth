package vkoauth

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"vkoauth/display"
)

type AuthParams struct {
	State    string          // Произвольная строка, будет возвращена вместе с редиректом. Используется для защиты от CSRF атак
	Revoke   bool            // Обязательное подтверждение выдачи прав, даже если приложению уже были предоставлены права ранее
	GroupIds []int64         // Идентификаторы сообществ, токены которых нужно получить
	Display  display.Display // Стиль отображения страницы авторизации
}

// Создает URL, на который нужно направить пользователя для проведений авторизации методом Implicit Flow (клиентское приложение, не сервер)
func (v *Config) ImplicitFlowAuthUrl(params AuthParams, opts ...AuthOption) string {
	return v.buildAuthUrl(params, "token", opts...)
}

// Возвращает токен, полученный после прохождения авторизации методом Implicit Flow
// Принимает параметр query - декодированное значение REDIRECT_URI#{fragment}
// Используйте библиотеку url, чтобы получать фрагмент из URL быстрее
func (v *Config) ResultToken(query url.Values) (*Token, error) {
	err := v.getErrorFromQuery(query)
	if err != nil {
		return nil, err
	}

	token := Token{}
	for k := range query {
		if strings.HasPrefix(k, "access_token") {
			if k == "access_token" {
				// User token
				token.AccessToken = query.Get(k)
			} else {
				groupIdString := strings.Replace(k, "access_token_", "", 1)
				groupId, err := strconv.ParseInt(groupIdString, 10, 64)

				if err != nil {
					return nil, fmt.Errorf("parse group id in token error: %e, token key: %s", err, k)
				}

				token.Groups = append(token.Groups, &GroupToken{
					GroupId:     groupId,
					AccessToken: query.Get(k),
				})
			}
		}
	}

	expiresInVal := query.Get("expires_in")
	if expiresInVal != "" {
		expiresIn, err := strconv.ParseInt(expiresInVal, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse expires_in field error: %w", err)
		}
		if expiresIn != 0 {
			e := time.Now().Add(time.Duration(expiresIn) * time.Second)
			token.Expires = &e
		}
	}

	userIdVal := query.Get("user_id")
	if userIdVal != "" {
		userId, err := strconv.ParseInt(userIdVal, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse user_id field error: %w", err)
		}
		token.UserId = userId
	}

	token.State = query.Get("state")

	raw := make(map[string]interface{}, len(query))
	for k := range query {
		raw[k] = query.Get(k)
	}

	token.Raw = raw
	return &token, nil
}
