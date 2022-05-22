package vkoauth_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"vkoauth"
)

type TokenCase struct {
	Body          string
	ExpectedToken vkoauth.AccessTokenJson
	IsNilExpires  bool
}

func TestAccessTokenJson(t *testing.T) {
	cases := []TokenCase{
		{
			Body:          `{}`,
			ExpectedToken: vkoauth.AccessTokenJson{},
		},
		{
			Body: `{"access_token":"533bacf01e11f55b536a565b57531ac114461ae8736d6506a3","expires_in":43200,"user_id":66748}`,
			ExpectedToken: vkoauth.AccessTokenJson{
				AccessToken: "533bacf01e11f55b536a565b57531ac114461ae8736d6506a3",
				ExpiresIn:   43200,
				UserId:      66748,
			},
		},
		{
			Body: `{"access_token_123456":"533bacf01e11f55b536a565b57531ac114461ae8736d6506a3","access_token_654321":"a740d2bfe91caaa6eab794e1168da38cdaedc93c92f233638f","groups":[{"group_id":123456,"access_token":"533bacf01e11f55b536a565b57531ac114461ae8736d6506a3"},{"group_id":654321,"access_token":"a740d2bfe91caaa6eab794e1168da38cdaedc93c92f233638f"}],"expires_in":0}`,
			ExpectedToken: vkoauth.AccessTokenJson{
				Groups: []struct {
					GroupId     int64  `json:"group_id"`
					AccessToken string `json:"access_token"`
				}{
					{
						GroupId:     123456,
						AccessToken: "533bacf01e11f55b536a565b57531ac114461ae8736d6506a3",
					},
					{
						GroupId:     654321,
						AccessToken: "a740d2bfe91caaa6eab794e1168da38cdaedc93c92f233638f",
					},
				},
			},
		},
	}

	for _, testCase := range cases {
		token := vkoauth.AccessTokenJson{}
		err := json.Unmarshal([]byte(testCase.Body), &token)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(token, testCase.ExpectedToken) {
			t.Errorf("unexpected token: %q, in %v", testCase.Body, token)
		}
	}
}
