package vkoauth

import "net/url"

// Интерфейс опции авторизации
type AuthOption interface {
	setValue(u url.Values)
}

type setParam struct{ k, v string }

func (v setParam) setValue(u url.Values) {
	u.Set(v.k, v.v)
}

// Опция, которая задает кастомный параметр URL
func SetUrlParam(key, val string) AuthOption {
	return setParam{key, val}
}
