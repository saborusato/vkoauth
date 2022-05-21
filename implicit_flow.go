package vkoauth

import "vkoauth/display"

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
