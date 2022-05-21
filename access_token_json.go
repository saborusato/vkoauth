package vkoauth

import "time"

// Структура, описывающая JSON схему результата получения токена
type AccessTokenJson struct {
	AccessToken string `json:"access_token"`
	UserId      int64  `json:"user_id"`
	ExpiresIn   int    `json:"expires_in"`
	Groups      []struct {
		GroupId     int64  `json:"group_id"`
		AccessToken string `json:"access_token"`
	} `json:"groups"`
}

func (v *AccessTokenJson) expires() *time.Time {
	if v.ExpiresIn <= 0 {
		return nil
	}
	t := time.Now().Add(time.Duration(v.ExpiresIn) * time.Second)
	return &t
}
