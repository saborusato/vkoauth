package vkoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ciricc/vkoauth/scope"
)

var DefaultVersion = "5.131" // Версия API ВКонтакте по умолчанию
var DefaultVkEndpoint = &Endpoint{
	AuthUrl:          "https://oauth.vk.com/authorize",
	PasswordTokenUrl: "https://oauth.vk.com/token",
	TokenUrl:         "https://oauth.vk.com/access_token",
} // Конфигурация API ВКонтакте по умолчанию

type Endpoint struct {
	AuthUrl          string // URL страницы, на которой будет проходить авторизация пользователя
	PasswordTokenUrl string // URL страницы, на которую будет отправляться запрос на получение токена по логину и пароля
	TokenUrl         string // URL страницы, на которую будет отправляться запрос на получение токена после прохождения аутентификации
}

// Конфигурация OAuth
// Для указания scope, используйте побитовое сложение (scope.User.photos | scope.User.Wall)
// или используйте значение scope.User.All, чтобы запросить все права
type Config struct {
	ClientId     string // Идентификатор приложения
	ClientSecret string // Секретный ключ приложения
	Version      string // Версия API ВК
	Endpoint     *Endpoint
	Scope        scope.Scope // Права доступа
	RedirectUri  string      // Ссылка, на которую будет перенаправлен пользователь после успешного прохождения аутентификации
}

type GroupToken struct {
	GroupId     int64
	AccessToken string
}

type Token struct {
	Groups      []*GroupToken          // Список токенов сообществ
	AccessToken string                 // Токен пользователя или приложения
	UserId      int64                  // Идентификатор пользователя (0, если получен токен приложения или сообщества)
	Expires     *time.Time             // Дата истечения токена (nil, если токен бессрочный)
	State       string                 // Произвольная строка, идентично значению параметра state в URL страницы авторизации (только Implicit Flow)
	Raw         map[string]interface{} // JSON Map ответа сервера, используйте, для получения дополнительных полей
}

// Возвращает конфигурацию API
func (v *Config) endpoint() *Endpoint {
	if v.Endpoint == nil {
		return DefaultVkEndpoint
	}
	return v.Endpoint
}

// Создает URL, на который нужно направить пользователя для проведения авторизации
func (v *Config) buildAuthUrl(params AuthParams, responseType string, opts ...AuthOption) string {
	u := url.Values{}

	if params.Display != "" {
		u.Set("display", string(params.Display))
	}

	u.Set("v", v.version())

	if v.Scope != 0 {
		u.Set("scope", strconv.FormatInt(int64(v.Scope), 10))
	}

	u.Set("redirect_uri", v.RedirectUri)
	u.Set("client_id", v.ClientId)
	u.Set("response_type", responseType)

	if params.State != "" {
		u.Set("state", params.State)
	}

	if params.Revoke {
		u.Set("revoke", "1")
	}

	if len(params.GroupIds) > 0 {
		idsStrings := make([]string, len(params.GroupIds))
		for i, id := range params.GroupIds {
			idsStrings[i] = strconv.FormatInt(id, 10)
		}
		u.Set("group_ids", strings.Join(idsStrings, ","))
	}

	for _, opt := range opts {
		if opt != nil {
			opt.setValue(u)
		}
	}

	uri := v.endpoint().AuthUrl

	if strings.Contains(uri, "?") {
		uri += "&"
	} else {
		uri += "?"
	}

	uri += u.Encode()
	return uri
}

// Делает запрос на получение токена по указанному URL
func (v *Config) doTokenRequest(ctx context.Context, reqUrl string) (*Token, error) {
	client := ContextClient(ctx)
	if client == nil {
		return nil, fmt.Errorf("http client is nil")
	}

	url, err := url.Parse(reqUrl)
	if err != nil {
		return nil, err
	}

	rawQ := url.RawQuery
	url.RawQuery = ""

	res, err := client.Post(url.String(), "application/x-www-form-urlencoded; charset=utf-8", strings.NewReader(rawQ))
	if err != nil {
		return nil, err
	}

	b, err := io.ReadAll(io.NopCloser(res.Body))
	if err != nil {
		return nil, err
	}

	res.Body.Close()
	if code := res.StatusCode; code < 200 || code > 299 {

		tokenErrorJson := TokenErrorJson{}
		json.Unmarshal(b, &tokenErrorJson)

		return nil, &TokenError{
			Response:         res,
			Body:             b,
			RedirectURI:      tokenErrorJson.RedirectURI,
			ErrorCode:        tokenErrorJson.Error,
			ValidationType:   tokenErrorJson.ValidationType,
			ValidationSid:    tokenErrorJson.ValidationSid,
			PhoneMask:        tokenErrorJson.PhoneMask,
			ValidationResend: tokenErrorJson.ValidationResend,
			CaptchaSid:       tokenErrorJson.CaptchaSid,
			CaptchaImg:       tokenErrorJson.CaptchaImg,
			description:      tokenErrorJson.ErrorDescription,
			ErrorType:        tokenErrorJson.ErrorType,
		}
	}

	tokenJson := AccessTokenJson{}

	err = json.Unmarshal(b, &tokenJson)
	if err != nil {
		return nil, err
	}

	token := &Token{
		AccessToken: tokenJson.AccessToken,
		UserId:      tokenJson.UserId,
		Expires:     tokenJson.expires(),
		Raw:         make(map[string]interface{}),
	}

	json.Unmarshal(b, &token.Raw)
	if len(tokenJson.Groups) > 0 {
		token.Groups = make([]*GroupToken, len(tokenJson.Groups))
		for i, tokenGroup := range tokenJson.Groups {
			token.Groups[i] = &GroupToken{
				GroupId:     tokenGroup.GroupId,
				AccessToken: tokenGroup.AccessToken,
			}
		}
	}

	return token, nil
}

// Возвращает версию API из конфига или берет значение по умолчанию
func (v *Config) version() string {

	if v.Version == "" {
		return DefaultVersion
	}

	return v.Version
}

// Создает URL для запроса на получение токена
func (v *Config) buildTokenUrl(baseUrl string, opts ...AuthOption) string {
	u := url.Values{}

	u.Set("client_id", v.ClientId)
	u.Set("client_secret", v.ClientSecret)
	u.Set("v", v.version())

	for _, opt := range opts {
		if opt != nil {
			opt.setValue(u)
		}
	}

	uri := baseUrl

	if strings.Contains(uri, "?") {
		uri += "&"
	} else {
		uri += "?"
	}

	uri += u.Encode()
	return uri
}

// Возвращает информацию об ошибке из URL
func (v *Config) getErrorFromQuery(query url.Values) error {
	errCode := query.Get("error")
	errDesc := query.Get("error_description")
	if errCode != "" || errDesc != "" {
		return &TokenError{
			Body:        []byte(query.Encode()),
			ErrorCode:   errCode,
			description: errDesc,
		}
	}
	return nil
}
