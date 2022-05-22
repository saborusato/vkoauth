package scope

import "testing"

func TestFullFlag(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		f1 := 1 << 0
		r := FullFlag(0) // 0 + 1 (= 1) bit == 1

		if r != uint(f1) {
			t.Errorf("unexpected value: %d", r)
		}
	})

	t.Run("sum flags", func(t *testing.T) {
		f1 := 1 << 0
		f2 := 1 << 1
		f3 := 1 << 2

		if uint(f1|f2|f3) != FullFlag(2) {
			t.Errorf("unexpected sum: %d, expected: %d", FullFlag(4), (f1 | f2 | f3))
		}
	})
}
