package scope

type Scope int
type ContextKey struct{}

// Права доступа для пользователя, используйте побитовое ИЛИ, чтобы сложить права вместе
// User.Docs | User.Offline или используйте User.All
var User = struct {
	Notify, Friends, Photos,
	Audio, Video, Stories,
	Pages, Plus256,
	Status, Notes, Messages,
	Wall, Ads, Offline,
	Docs, Groups, Notifications,
	State, Market, Email, Stats, All Scope
}{
	Notify:        1 << 0,
	Friends:       1 << 1,
	Photos:        1 << 2,
	Audio:         1 << 3,
	Video:         1 << 4,
	Stories:       1 << 6,
	Pages:         1 << 7,
	Plus256:       1 << 8,
	Status:        1 << 10,
	Notes:         1 << 11,
	Messages:      1 << 12,
	Wall:          1 << 13,
	Ads:           1 << 15,
	Offline:       1 << 16,
	Docs:          1 << 17,
	Groups:        1 << 18,
	Notifications: 1 << 19,
	Stats:         1 << 20,
	Email:         1 << 22,
	Market:        1 << 27,
	All:           Scope(AllMask(27)),
}

// Права доступа для сообществ, используйте побитовое ИЛИ, чтобы сложить права вместе
// Group.Stories | Group.Photos или используйте Group.All
var Group = struct {
	Stories,
	Photos,
	AppWidget,
	Messages,
	Docs,
	Manage,
	All Scope
}{
	Stories:   1 << 0,
	Photos:    1 << 2,
	AppWidget: 1 << 6,
	Messages:  1 << 12,
	Docs:      1 << 17,
	Manage:    1 << 18,
	All:       Scope(AllMask(18)),
}

// Возвращает число, (maxVal + 1) первых битов которого = 1
func AllMask(maxVal int) int {
	v := 1
	for i := 0; i < int(maxVal); i++ {
		v = (v << 1) | 1
	}
	return v
}
