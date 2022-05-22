package vkoauth_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"vkoauth"
	"vkoauth/display"
	"vkoauth/scope"
)

var LocalEndpoint = vkoauth.Endpoint{
	AuthUrl:          "http://localhost:9000/authorize",
	PasswordTokenUrl: "http://localhost:9000/token",
	TokenUrl:         "http://localhost:9000/access_token",
}

func TestVkOauthDefaultValues(t *testing.T) {
	c := vkoauth.Config{
		ClientId:     "2274003",
		ClientSecret: "secret",
		Scope:        scope.Group.Photos | scope.User.Wall,
		RedirectUri:  "blank.html",
	}

	t.Run("build implicit flow url", func(t *testing.T) {
		url := c.ImplicitFlowAuthUrl(vkoauth.AuthParams{}, vkoauth.SetUrlParam("foo", "bar"))
		expectedUrl := "https://oauth.vk.com/authorize?client_id=2274003&foo=bar&redirect_uri=blank.html&response_type=token&scope=8196&v=5.131"
		if url != expectedUrl {
			t.Errorf("expected auth url: %q, real: %q", expectedUrl, url)
		}
	})

	t.Run("build implicit flow url with params", func(t *testing.T) {
		url := c.ImplicitFlowAuthUrl(vkoauth.AuthParams{
			Revoke:   true,
			State:    "1234",
			GroupIds: []int64{1, 2, 3},
			Display:  display.Popup,
		}, vkoauth.SetUrlParam("foo", "bar"))
		expectedUrl := "https://oauth.vk.com/authorize?client_id=2274003&display=popup&foo=bar&group_ids=1%2C2%2C3&redirect_uri=blank.html&response_type=token&revoke=1&scope=8196&state=1234&v=5.131"
		if expectedUrl != url {
			t.Errorf("expected auth url: %q, real: %q", expectedUrl, url)
		}
	})
}

func TestVkOauthExchangeRequest(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected request method: %v", r.Method)
		}

		if r.URL.RawQuery != "" {
			t.Errorf("unexpected url raw query: %q", r.URL.RawQuery)
		}

		if r.Header.Get("content-type") != "application/x-www-form-urlencoded; charset=utf-8" {
			t.Errorf("unexpected content type header: %q", r.Header.Get("content-type"))
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}

		q, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			t.Error(err)
		}

		if q.Encode() != "client_id=CLIENT_ID&client_secret=CLIENT_SECRET&code=exchange-code&key=value&redirect_uri=REDIRECT_URI&v=VERSION" {
			t.Errorf("unexpected request body: %q", q.Encode())
		}
	}))

	defer serv.Close()
	c := conf(serv.URL)

	t.Run("build implicit flow url", func(t *testing.T) {
		url := c.ImplicitFlowAuthUrl(vkoauth.AuthParams{}, vkoauth.SetUrlParam("custom_parameter_key", "value"))
		expectedUrl := serv.URL + "?client_id=CLIENT_ID&custom_parameter_key=value&redirect_uri=REDIRECT_URI&response_type=token&scope=8193&v=VERSION"
		if url != expectedUrl {
			t.Errorf("expected auth url: %q, real: %q", expectedUrl, url)
		}
	})

	t.Run("authorization code flow", func(t *testing.T) {
		url := c.CodeFlowAuthUrl(vkoauth.AuthParams{})
		expectedUrl := serv.URL + "?client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&response_type=code&scope=8193&v=VERSION"
		if url != expectedUrl {
			t.Errorf("expected auth url: %q, real: %q", expectedUrl, url)
		}
	})

	t.Run("exchange code", func(t *testing.T) {
		c.ExchangeCode(context.Background(), "exchange-code", vkoauth.SetUrlParam("key", "value"))
	})
}

func TestTokenResponseParsingError(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_grant","error_description": "Code is expired."}`))
	}))
	defer serv.Close()
	c := conf(serv.URL)

	_, err := c.ExchangeCode(context.Background(), "")
	if err != nil {
		if errorObject, ok := err.(*vkoauth.TokenError); ok {
			if errorObject.ErrorCode != "invalid_grant" {
				t.Errorf("unexpected error code: %q", string(errorObject.Body))
			}
			if string(errorObject.Body) != `{"error": "invalid_grant","error_description": "Code is expired."}` {
				t.Errorf("unexpected response body: %q", string(errorObject.Body))
			}
		} else {
			t.Error(err)
		}
	} else {
		t.Errorf("expected error, but nothing got")
	}
}

func conf(u string) vkoauth.Config {
	return vkoauth.Config{
		ClientId:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		Version:      "VERSION",
		Scope:        scope.User.Wall | scope.Group.Stories,
		RedirectUri:  "REDIRECT_URI",
		Endpoint: &vkoauth.Endpoint{
			AuthUrl:          u,
			TokenUrl:         u,
			PasswordTokenUrl: u,
		},
	}
}

func TestTokenResponseSuccessGroups(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token_123456":"533bacf01e11f55b536a565b57531ac114461ae8736d6506a3","access_token_654321":"a740d2bfe91caaa6eab794e1168da38cdaedc93c92f233638f","groups":[{"group_id":123456,"access_token":"533bacf01e11f55b536a565b57531ac114461ae8736d6506a3"},{"group_id":654321,"access_token":"a740d2bfe91caaa6eab794e1168da38cdaedc93c92f233638f"}],"expires_in":0}`))
	}))

	defer serv.Close()
	c := conf(serv.URL)

	token, err := c.ExchangeCode(context.Background(), "")
	if err != nil {
		t.Error(err)
	}

	if token == nil {
		t.Errorf("unexpected response: %v", token)
	}

	if len(token.Groups) == 0 {
		t.Errorf("unexpected groups tokens count: %v", token)
	}

	if token.Expires != nil {
		t.Errorf("unexpected expiriation date: %v", token.Expires)
	}

	expectedTokens := []*vkoauth.GroupToken{
		{
			GroupId:     123456,
			AccessToken: "533bacf01e11f55b536a565b57531ac114461ae8736d6506a3",
		},
		{
			GroupId:     654321,
			AccessToken: "a740d2bfe91caaa6eab794e1168da38cdaedc93c92f233638f",
		},
	}

	if !reflect.DeepEqual(token.Groups, expectedTokens) {
		t.Errorf("Unexpected tokens: %v", token.Groups)
	}

	if token.UserId != 0 {
		t.Errorf("unexpected user_id value: %d", token.UserId)
	}

	if token.AccessToken != "" {
		t.Errorf("unexpected access token value: %q", token.AccessToken)
	}

	if _, ok := token.Raw["access_token_123456"]; !ok {
		t.Errorf("unexpected custom raw field in token")
	}

}

func TestTokenResponseSuccessUser(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"533bacf01e11f55b536a565b57531ac114461ae8736d6506a3","expires_in":43200,"user_id":66748,"first_name":"Витя","last_name":"AK"}`))
	}))

	defer serv.Close()
	c := conf(serv.URL)

	token, err := c.ExchangeCode(context.Background(), "exchange-code")
	if err != nil {
		t.Error(err)
	}

	if token.UserId != 66748 {
		t.Errorf("unexpected user id value: %d", token.UserId)
	}
	if token.AccessToken != "533bacf01e11f55b536a565b57531ac114461ae8736d6506a3" {
		t.Errorf("unexpected token: %q", token.AccessToken)
	}

	if token.Expires == nil {
		t.Errorf("unexpected expires value: %v", token.Expires)
	}

	if _, ok := token.Raw["first_name"]; !ok {
		t.Errorf("unexpected first name field: %v", token.Raw)
	}
}

func TestPasswordResponseCaptcha(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"need_captcha","captcha_sid":"854844498568","captcha_img":"http://api.vk.com/captcha.php?sid=854844498568&s=1"}`))
	}))

	defer serv.Close()
	c := conf(serv.URL)
	token, err := c.PasswordCredentials(context.Background(), vkoauth.TokenParams{})
	if err != nil {
		if errObject, ok := err.(*vkoauth.TokenError); ok {
			if errObject.ErrorCode != "need_captcha" {
				t.Errorf("unexpected error code: %q", errObject.ErrorCode)
			}
			if errObject.CaptchaSid != "854844498568" {
				t.Errorf("unexpected captcha sid: %q", errObject.CaptchaSid)
			}
			if errObject.CaptchaImg != "http://api.vk.com/captcha.php?sid=854844498568&s=1" {
				t.Errorf("unexpected captcha img: %q", errObject.CaptchaImg)
			}
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	} else {
		t.Errorf("unexpected error value: %v %v", err, token)
	}
}

func TestPasswordResponseNeedValidation(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"need_validation","error_description":"please open redirect_uri in browser","redirect_uri":"https://oauth.vk.com/security_check?type=test&mid=66748&hash=23132d8b8744f8b1b2"}`))
	}))

	defer serv.Close()
	c := conf(serv.URL)
	token, err := c.PasswordCredentials(context.Background(), vkoauth.TokenParams{})

	if err != nil {
		if errObject, ok := err.(*vkoauth.TokenError); ok {
			if errObject.ErrorCode != "need_validation" {
				t.Errorf("unexpected error code: %q", errObject.ErrorCode)
			}
			if errObject.RedirectURI != "https://oauth.vk.com/security_check?type=test&mid=66748&hash=23132d8b8744f8b1b2" {
				t.Errorf("unexpected redirect uri: %q", errObject.RedirectURI)
			}
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	} else {
		t.Errorf("unexpected error value: %v %v", err, token)
	}
}

func TestPasswordRequest(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected request method: %v", r.Method)
		}

		if r.URL.RawQuery != "" {
			t.Errorf("unexpected url raw query: %q", r.URL.RawQuery)
		}

		if r.Header.Get("content-type") != "application/x-www-form-urlencoded; charset=utf-8" {
			t.Errorf("unexpected content type header: %q", r.Header.Get("content-type"))
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}

		q, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			t.Error(err)
		}

		if q.Encode() != "2fa_supported=1&captcha_key=abc&captcha_sid=12345&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&code=12345&foo=bar&grant_type=password&password=PASSWORD&scope=8193&test_redirect_uri=1&username=USERNAME&v=VERSION" {
			t.Errorf("unexpected request body: %q", q.Encode())
		}
	}))

	defer serv.Close()
	c := conf(serv.URL)

	c.PasswordCredentials(context.Background(), vkoauth.TokenParams{
		TestRedirectUri: true,
		TwoFaSupported:  true,
		Username:        "USERNAME",
		Password:        "PASSWORD",
		Code:            "12345",
		CaptchaSid:      "12345",
		CaptchaKey:      "abc",
	}, vkoauth.SetUrlParam("foo", "bar"))
}

func TestPasswordResponseToken(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"9d77c727986d7668986d7668049870402D1986d986d76684bbc9b1bf8488de9","expires_in":0,"user_id":85635407}`))
	}))

	defer serv.Close()
	c := conf(serv.URL)
	token, err := c.PasswordCredentials(context.Background(), vkoauth.TokenParams{})
	if err != nil {
		t.Error(err)
	}

	if token.UserId != 85635407 {
		t.Errorf("unexpected user id: %d", token.UserId)
	}

	if token.AccessToken != "9d77c727986d7668986d7668049870402D1986d986d76684bbc9b1bf8488de9" {
		t.Errorf("unexpected access token: %v", "9d77c727986d7668986d7668049870402D1986d986d76684bbc9b1bf8488de9")
	}

	if token.Expires != nil {
		t.Errorf("unexpected expiration date: %v", token.Expires)
	}
}

func TestPasswordCustomHttpClientIsNilNoPanic(t *testing.T) {
	c := conf("")
	c.PasswordCredentials(context.WithValue(context.Background(), vkoauth.HTTPClient, nil), vkoauth.TokenParams{})
}

type CustomRoundTripper struct {
	t       http.RoundTripper
	Tripped bool
}

func (v *CustomRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	v.Tripped = true
	return v.t.RoundTrip(req)
}

func TestPasswordCustomHttpClient(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))

	defer serv.Close()
	c := conf(serv.URL)

	ct := CustomRoundTripper{
		t: http.DefaultTransport,
	}

	httpClient := &http.Client{
		Transport: &ct,
	}

	c.PasswordCredentials(context.WithValue(context.Background(), vkoauth.HTTPClient, httpClient), vkoauth.TokenParams{})
	if !ct.Tripped {
		t.Errorf("unused http client from context")
	}
}

func TestExchangeCpdeCustomHttpClient(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))

	defer serv.Close()
	c := conf(serv.URL)

	ct := CustomRoundTripper{
		t: http.DefaultTransport,
	}

	httpClient := &http.Client{
		Transport: &ct,
	}

	c.ExchangeCode(context.WithValue(context.Background(), vkoauth.HTTPClient, httpClient), "")
	if !ct.Tripped {
		t.Errorf("unused http client from context")
	}
}

func TestClientCredentialsRequest(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected request method: %v", r.Method)
		}

		if r.URL.RawQuery != "" {
			t.Errorf("unexpected url raw query: %q", r.URL.RawQuery)
		}

		if r.Header.Get("content-type") != "application/x-www-form-urlencoded; charset=utf-8" {
			t.Errorf("unexpected content type header: %q", r.Header.Get("content-type"))
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}

		q, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			t.Error(err)
		}

		if q.Encode() != "client_id=CLIENT_ID&client_secret=CLIENT_SECRET&foo=bar&grant_type=client_credentials&v=VERSION" {
			t.Errorf("unexpected request body: %q", q.Encode())
		}
	}))

	defer serv.Close()
	c := conf(serv.URL)

	c.GetServiceToken(context.Background(), vkoauth.SetUrlParam("foo", "bar"))
}

func TestClientCredentialsSponseSuccess(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"533bacf01e11f55b536a565b57531ac114461ae8736d6506a3"}`))
	}))

	defer serv.Close()
	c := conf(serv.URL)

	token, err := c.GetServiceToken(context.Background())
	if err != nil {
		t.Error(err)
	}

	if token.AccessToken != "533bacf01e11f55b536a565b57531ac114461ae8736d6506a3" {
		t.Errorf("unexpected token value: %q", token.AccessToken)
	}
}

func TestRewriteImplicitFlowUrlValues(t *testing.T) {
	c := conf("")

	u := c.ImplicitFlowAuthUrl(vkoauth.AuthParams{
		State: "origin_state",
	}, vkoauth.SetUrlParam("state", "new_state"), vkoauth.SetUrlParam("client_id", "new_client_id"))

	if u != "?client_id=new_client_id&redirect_uri=REDIRECT_URI&response_type=token&scope=8193&state=new_state&v=VERSION" {
		t.Errorf("unexpected url: %q", u)
	}
}

func TestRewriteClientCredentialsRequestValues(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(bodyBytes) != "client_id=CLIENT_ID&client_secret=new_client_secret&foo=bar&grant_type=client_credentials&v=VERSION" {
			t.Errorf("unexpected body: %q", string(bodyBytes))
		}
	}))

	defer serv.Close()
	c := conf(serv.URL)

	c.GetServiceToken(context.Background(), vkoauth.SetUrlParam("foo", "bar"), vkoauth.SetUrlParam("client_secret", "new_client_secret"))
}

func TestRewritePasswordRequestValues(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(bodyBytes) != "client_id=CLIENT_ID&client_secret=new_client_secret&foo=bar&grant_type=password&password=&scope=8193&username=&v=VERSION" {
			t.Errorf("unexpected body: %q", string(bodyBytes))
		}
	}))

	defer serv.Close()
	c := conf(serv.URL)

	c.PasswordCredentials(context.Background(), vkoauth.TokenParams{}, vkoauth.SetUrlParam("foo", "bar"), vkoauth.SetUrlParam("client_secret", "new_client_secret"))
}

func TestRewriteExchangeCodeRequestValues(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(bodyBytes) != "client_id=CLIENT_ID&client_secret=new_client_secret&code=&foo=bar&redirect_uri=REDIRECT_URI&v=VERSION" {
			t.Errorf("unexpected body: %q", string(bodyBytes))
		}
	}))

	defer serv.Close()
	c := conf(serv.URL)

	c.ExchangeCode(context.Background(), "", vkoauth.SetUrlParam("foo", "bar"), vkoauth.SetUrlParam("client_secret", "new_client_secret"))
}
