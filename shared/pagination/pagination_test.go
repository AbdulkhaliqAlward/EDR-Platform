package pagination

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func opts() Options {
	return Options{Scope: "alerts", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}, Now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
}
func TestParseBounds(t *testing.T) {
	for _, tc := range []struct {
		query string
		limit int
		bad   bool
	}{{"", 25, false}, {"limit=999", 100, false}, {"limit=0", 0, true}, {"limit=-1", 0, true}, {"limit=no", 0, true}, {"sort=raw", 0, true}, {"order=DROP", 0, true}, {"offset=10", 0, true}, {"cursor=garbage", 0, true}, {"include_total=no", 0, true}} {
		t.Run(tc.query, func(t *testing.T) {
			q, _ := url.ParseQuery(tc.query)
			p, e := Parse(q, opts())
			if (e != nil) != tc.bad {
				t.Fatalf("unexpected error %v", e)
			}
			if e == nil && p.Limit != tc.limit {
				t.Fatalf("limit %d", p.Limit)
			}
		})
	}
}
func TestForwardReversePrecisionAndBinding(t *testing.T) {
	q := url.Values{"limit": {"2"}, "status": {"open"}}
	p, e := Parse(q, opts())
	if e != nil {
		t.Fatal(e)
	}
	now := p.Until.Add(-time.Second).Add(123456 * time.Nanosecond)
	key := func(id string) Key { return TimeKey(now, id) }
	page := Build([]string{"c", "b", "a"}, p, key)
	if !page.PageInfo.HasNext || page.PageInfo.HasPrev || len(page.Data) != 2 {
		t.Fatal(page)
	}
	q.Set("cursor", *page.PageInfo.NextCursor)
	p, e = Parse(q, opts())
	if e != nil {
		t.Fatal(e)
	}
	if p.Key.Value != now.Format(time.RFC3339Nano) || p.Key.ID != "b" {
		t.Fatal(p.Key)
	}
	args := []any{}
	where, order, e := p.Keyset("created_at", "id", &args)
	if e != nil || !strings.Contains(where, " < ") || order != "created_at DESC, id DESC" {
		t.Fatal(where, order, e)
	}
	back := Build([]string{"a"}, p, key)
	q.Set("cursor", *back.PageInfo.PrevCursor)
	p, e = Parse(q, opts())
	if e != nil {
		t.Fatal(e)
	}
	where, order, e = p.Keyset("created_at", "id", &args)
	if e != nil || !strings.Contains(where, " > ") || order != "created_at ASC, id ASC" {
		t.Fatal(where, order, e)
	}
	prev := Build([]string{"b", "c"}, p, key)
	if strings.Join(prev.Data, "") != "cb" || prev.PageInfo.HasPrev || !prev.PageInfo.HasNext {
		t.Fatal(prev)
	}
	q.Set("status", "closed")
	if _, e = Parse(q, opts()); e == nil {
		t.Fatal("accepted changed filter")
	}
}
func TestTamperEmptyAndExactlyLimit(t *testing.T) {
	p, _ := Parse(url.Values{"limit": {"2"}}, opts())
	k := func(v string) Key { return TimeKey(p.Until, v) }
	for _, rows := range [][]string{nil, {"a", "b"}} {
		pg := Build(rows, p, k)
		if pg.PageInfo.HasNext || pg.Data == nil {
			t.Fatal(pg)
		}
	}
	pg := Build([]string{"c", "b", "a"}, p, k)
	token := *pg.PageInfo.NextCursor
	token = "A" + token[1:]
	if _, e := Parse(url.Values{"limit": {"2"}, "cursor": {token}}, opts()); e == nil {
		t.Fatal("accepted tampered cursor")
	}
	p.Cursor = "present"
	p.Key = Key{Value: "null", ID: "x"}
	args := []any{}
	if _, _, e := p.Keyset("created_at", "id", &args); e == nil {
		t.Fatal("accepted null/non-time key")
	}
}
func TestIntegerKeyset(t *testing.T) {
	o := opts()
	o.Sorts = map[string]string{"created_at": "created_at", "risk_score": "risk_score"}
	q := url.Values{"sort": {"risk_score"}, "order": {"desc"}, "limit": {"1"}}
	p, e := Parse(q, o)
	if e != nil {
		t.Fatal(e)
	}
	pg := Build([]int{90, 90}, p, func(v int) Key { return IntKey(int64(v), "id") })
	q.Set("cursor", *pg.PageInfo.NextCursor)
	if p, e = Parse(q, o); e != nil {
		t.Fatal(e)
	}
	args := []any{}
	where, order, e := p.KeysetInt("risk_score", "id", &args)
	if e != nil || args[0] != int64(90) || !strings.Contains(where, "(risk_score, id) < ") || order != "risk_score DESC, id DESC" {
		t.Fatal(where, order, args, e)
	}
	// A time cursor must not be accepted where an integer key is expected.
	p.Key.Value = "2026-10-10T12:00:00Z"
	if _, _, e = p.KeysetInt("risk_score", "id", &args); e == nil {
		t.Fatal("accepted non-integer key")
	}
	// Changing the sort invalidates the cursor.
	q.Set("sort", "created_at")
	if _, e = Parse(q, o); e == nil {
		t.Fatal("accepted cursor for another sort")
	}
}
func TestOffsetAndOptionalTotal(t *testing.T) {
	o := opts()
	o.Offset = true
	p, e := Parse(url.Values{"page": {"3"}, "limit": {"25"}}, o)
	if e != nil || p.Offset != 50 {
		t.Fatal(p, e)
	}
	pg := BuildOffset([]int{1}, p)
	if !pg.PageInfo.HasPrev || pg.PageInfo.HasNext {
		t.Fatal(pg)
	}
	if !CappedTotal(10001).Capped || CappedTotal(10001).Value != 10000 || CappedTotal(10000).Capped {
		t.Fatal("cap")
	}
}
