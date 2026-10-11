// Package pagination implements bounded, filter-bound navigation contracts.
// It never authorizes access: callers must still apply their normal ACL filters.
package pagination

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const DefaultLimit = 25
const MaxLimit = 100
const CountCap = 10000
const QueryTimeout = 5 * time.Second

var ErrCursor = errors.New("invalid or expired cursor; return to the first page")
var signing = struct {
	sync.RWMutex
	key []byte
}{key: randomKey()}

func randomKey() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ConfigureKey derives a domain-separated cursor key from an existing server
// secret. Call once at startup, before accepting requests. No key is serialized.
// An empty secret retains a process-local key (isolated tests only).
func ConfigureKey(secret []byte) {
	if len(secret) == 0 {
		return
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("mitras/pagination/v1"))
	signing.Lock()
	signing.key = h.Sum(nil)
	signing.Unlock()
}

type Key struct {
	Value string `json:"k"`
	ID    string `json:"id"`
}
type cursor struct {
	Version int       `json:"v"`
	Scope   string    `json:"s"`
	Sort    string    `json:"sort"`
	Order   string    `json:"order"`
	Before  bool      `json:"before,omitempty"`
	Key     Key       `json:"key"`
	From    time.Time `json:"from"`
	Until   time.Time `json:"until"`
	Offset  int       `json:"offset,omitempty"`
}
type Params struct {
	Limit        int
	Sort, Order  string
	IncludeTotal bool
	Cursor       string
	Key          Key
	Before       bool
	From, Until  time.Time
	Offset       int
	scope        string
}
type Options struct {
	Scope, DefaultSort string
	Sorts              map[string]string // caller-owned whitelist of API names to SQL expressions
	Offset             bool
	Window             time.Duration
	Now                time.Time
}
type PageInfo struct {
	Limit      int     `json:"limit"`
	HasNext    bool    `json:"has_next"`
	HasPrev    bool    `json:"has_prev"`
	NextCursor *string `json:"next_cursor"`
	PrevCursor *string `json:"prev_cursor"`
}
type Total struct {
	Value  int  `json:"value"`
	Capped bool `json:"capped"`
}
type Page[T any] struct {
	Data     []T      `json:"data"`
	PageInfo PageInfo `json:"page_info"`
	Total    *Total   `json:"total,omitempty"`
}

func Parse(q url.Values, opt Options) (Params, error) {
	p := Params{Limit: DefaultLimit, Sort: opt.DefaultSort, Order: "desc", Cursor: q.Get("cursor")}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return p, errors.New("limit must be a positive integer")
		}
		p.Limit = min(n, MaxLimit)
	}
	if v := q.Get("sort"); v != "" {
		p.Sort = strings.TrimPrefix(v, "-")
		if !strings.HasPrefix(v, "-") && q.Get("order") == "" {
			p.Order = "asc"
		}
	}
	if v := q.Get("order"); v != "" {
		p.Order = v
	}
	if p.Order != "asc" && p.Order != "desc" {
		return p, errors.New("order must be asc or desc")
	}
	if _, ok := opt.Sorts[p.Sort]; !ok {
		return p, errors.New("unsupported sort column")
	}
	if v := q.Get("include_total"); v != "" {
		if v != "true" && v != "false" {
			return p, errors.New("include_total must be true or false")
		}
		p.IncludeTotal = v == "true"
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || (!opt.Offset && n != 0) {
			return p, errors.New("offset is not supported on this list; use cursor")
		}
		p.Offset = n
	}
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if !opt.Offset || err != nil || n < 1 || n > 1000000 {
			return p, errors.New("invalid page")
		}
		p.Offset = (n - 1) * p.Limit
	}
	if p.Offset > 100000000 {
		return p, errors.New("offset is too large")
	}
	filters := url.Values{}
	for k, v := range q {
		switch k {
		case "cursor", "limit", "offset", "page", "include_total", "sort", "order":
		default:
			filters[k] = v
		}
	}
	digest := sha256.Sum256([]byte(opt.Scope + "\n" + filters.Encode()))
	p.scope = hex.EncodeToString(digest[:])
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	p.Until = now.UTC().Truncate(time.Microsecond)
	window := opt.Window
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	p.From = p.Until.Add(-window)
	if p.Cursor != "" {
		c, err := decode(p.Cursor)
		if err != nil {
			return p, err
		}
		if c.Scope != p.scope || c.Sort != p.Sort || c.Order != p.Order || c.From.After(c.Until) || c.Until.After(now.Add(time.Minute)) {
			return p, ErrCursor
		}
		if opt.Offset {
			if c.Offset < 0 || c.Offset > 100000000 {
				return p, ErrCursor
			}
			p.Offset = c.Offset
		} else {
			if c.Key.ID == "" || len(c.Key.ID) > 128 || c.Key.Value == "" || len(c.Key.Value) > 256 {
				return p, ErrCursor
			}
		}
		p.Key, p.Before, p.From, p.Until = c.Key, c.Before, c.From, c.Until
	}
	return p, nil
}

func encode(c cursor) string {
	data, _ := json.Marshal(c)
	signing.RLock()
	h := hmac.New(sha256.New, signing.key)
	h.Write(data)
	mac := h.Sum(nil)
	signing.RUnlock()
	return base64.RawURLEncoding.EncodeToString(append(data, mac...))
}
func decode(token string) (cursor, error) {
	var c cursor
	if len(token) > 4096 {
		return c, ErrCursor
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(b) <= sha256.Size {
		return c, ErrCursor
	}
	data, mac := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
	signing.RLock()
	h := hmac.New(sha256.New, signing.key)
	h.Write(data)
	valid := hmac.Equal(mac, h.Sum(nil))
	signing.RUnlock()
	if !valid {
		return c, ErrCursor
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || c.Version != 1 || c.Until.IsZero() || c.From.IsZero() {
		return c, ErrCursor
	}
	if d.Decode(new(any)) != io.EOF {
		return c, ErrCursor
	}
	return c, nil
}
func (p Params) token(k Key, before bool, offset int) *string {
	s := encode(cursor{Version: 1, Scope: p.scope, Sort: p.Sort, Order: p.Order, Before: before, Key: k, From: p.From, Until: p.Until, Offset: offset})
	return &s
}

// Keyset uses trusted SQL expressions from the endpoint's static whitelist only.
// Timestamp keys are validated at this boundary so invalid cursors never reach SQL.
func (p Params) Keyset(column, id string, args *[]any) (string, string, error) {
	return p.keyset(column, id, args, func(v string) (any, error) { return time.Parse(time.RFC3339Nano, v) })
}

// KeysetInt is Keyset for a NOT NULL (or consistently COALESCEd) integer sort key.
func (p Params) KeysetInt(column, id string, args *[]any) (string, string, error) {
	return p.keyset(column, id, args, func(v string) (any, error) { return strconv.ParseInt(v, 10, 64) })
}

func (p Params) keyset(column, id string, args *[]any, parse func(string) (any, error)) (string, string, error) {
	direction, comparison := "DESC", "<"
	if p.Order == "asc" {
		direction, comparison = "ASC", ">"
	}
	if p.Before {
		if direction == "DESC" {
			direction, comparison = "ASC", ">"
		} else {
			direction, comparison = "DESC", "<"
		}
	}
	order := column + " " + direction + ", " + id + " " + direction
	if p.Cursor == "" {
		return "", order, nil
	}
	v, err := parse(p.Key.Value)
	if err != nil {
		return "", "", ErrCursor
	}
	*args = append(*args, v, p.Key.ID)
	return fmt.Sprintf(" AND (%s, %s) %s ($%d, $%d)", column, id, comparison, len(*args)-1, len(*args)), order, nil
}
func TimeKey(t time.Time, id string) Key { return Key{Value: t.UTC().Format(time.RFC3339Nano), ID: id} }
func IntKey(v int64, id string) Key      { return Key{Value: strconv.FormatInt(v, 10), ID: id} }

func Build[T any](rows []T, p Params, key func(T) Key) Page[T] {
	extra := len(rows) > p.Limit
	if extra {
		rows = rows[:p.Limit]
	}
	if rows == nil {
		rows = []T{}
	}
	if p.Before {
		for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
			rows[i], rows[j] = rows[j], rows[i]
		}
	}
	page := Page[T]{Data: rows, PageInfo: PageInfo{Limit: p.Limit}}
	if len(rows) == 0 {
		return page
	}
	page.PageInfo.HasNext, page.PageInfo.HasPrev = extra, p.Cursor != ""
	if p.Before {
		page.PageInfo.HasNext, page.PageInfo.HasPrev = true, extra
	}
	if page.PageInfo.HasNext {
		page.PageInfo.NextCursor = p.token(key(rows[len(rows)-1]), false, 0)
	}
	if page.PageInfo.HasPrev {
		page.PageInfo.PrevCursor = p.token(key(rows[0]), true, 0)
	}
	return page
}
func BuildOffset[T any](rows []T, p Params) Page[T] {
	page := Build(rows, Params{Limit: p.Limit}, func(T) Key { return Key{} })
	page.PageInfo.HasPrev = p.Offset > 0
	page.PageInfo.NextCursor = nil
	if page.PageInfo.HasNext {
		page.PageInfo.NextCursor = p.token(Key{}, false, p.Offset+p.Limit)
	}
	if page.PageInfo.HasPrev {
		page.PageInfo.PrevCursor = p.token(Key{}, false, max(0, p.Offset-p.Limit))
	}
	return page
}

func CappedTotal(n int) *Total { return &Total{Value: min(n, CountCap), Capped: n > CountCap} }
