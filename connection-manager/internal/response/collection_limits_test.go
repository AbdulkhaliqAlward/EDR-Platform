package response

import "testing"

func TestCollectionBoundsValidation(t *testing.T) {
	for _, tc := range []struct {
		p     actionParam
		value string
		valid bool
	}{
		{actionParam{Key: "max_events", Kind: "int"}, "200", true},
		{actionParam{Key: "max_events", Kind: "int"}, "5001", false},
		{actionParam{Key: "max_events", Kind: "int"}, "-1", false},
		{actionParam{Key: "time_range", Kind: "duration"}, "15m", true},
		{actionParam{Key: "time_range", Kind: "duration"}, "168h", true},
		{actionParam{Key: "time_range", Kind: "duration"}, "169h", false},
		{actionParam{Key: "time_range", Kind: "duration"}, "0s", false},
		{actionParam{Key: "time_range", Kind: "duration"}, "all", false},
	} {
		if err := validateParam(tc.p, tc.value); (err == nil) != tc.valid {
			t.Errorf("%s=%s: %v", tc.p.Key, tc.value, err)
		}
	}
}
