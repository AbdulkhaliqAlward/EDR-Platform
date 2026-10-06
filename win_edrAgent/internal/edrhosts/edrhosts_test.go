package edrhosts

import "testing"

func TestStripEntries(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		want        string
		wantChanged bool
	}{
		{
			name:        "no EDR entries is untouched",
			in:          "127.0.0.1 localhost\r\n10.0.0.5 intranet.corp\r\n",
			want:        "127.0.0.1 localhost\r\n10.0.0.5 intranet.corp\r\n",
			wantChanged: false,
		},
		{
			name:        "C2 mapping removed (CRLF preserved on other lines)",
			in:          "127.0.0.1 localhost\r\n51.20.76.95\tedr.local\t# EDR C2\r\n10.0.0.5 intranet.corp\r\n",
			want:        "127.0.0.1 localhost\r\n10.0.0.5 intranet.corp\r\n",
			wantChanged: true,
		},
		{
			name: "domain sinkhole blocks removed",
			in: "127.0.0.1 localhost\n" +
				"\n# EDR_BLOCK_BEGIN evil.com\n127.0.0.1 evil.com\n# EDR_BLOCK_END evil.com\n" +
				"\n# EDR_BLOCK_BEGIN bad.org\n127.0.0.1 bad.org\n# EDR_BLOCK_END bad.org\n",
			want:        "127.0.0.1 localhost\n\n\n",
			wantChanged: true,
		},
		{
			name: "user line inside a block is preserved",
			in: "# EDR_BLOCK_BEGIN evil.com\n127.0.0.1 evil.com\n" +
				"10.0.0.9 printer.corp\n# EDR_BLOCK_END evil.com\n",
			want:        "10.0.0.9 printer.corp\n",
			wantChanged: true,
		},
		{
			name:        "unterminated block keeps following user content",
			in:          "# EDR_BLOCK_BEGIN evil.com\n127.0.0.1 evil.com\n10.0.0.5 intranet.corp\n",
			want:        "10.0.0.5 intranet.corp\n",
			wantChanged: true,
		},
		{
			name:        "same IP mapping for another domain outside a block is kept",
			in:          "127.0.0.1 evil.com\n",
			want:        "127.0.0.1 evil.com\n",
			wantChanged: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := StripEntries(tt.in)
			if changed != tt.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tt.wantChanged)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
