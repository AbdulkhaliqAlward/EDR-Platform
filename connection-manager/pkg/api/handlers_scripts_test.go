package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/handlers"
	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
)

// memScriptRepo is an in-memory ResponseScriptRepository for handler tests.
type memScriptRepo struct {
	byID map[uuid.UUID]repository.ResponseScript
}

func newMemScriptRepo() *memScriptRepo {
	return &memScriptRepo{byID: map[uuid.UUID]repository.ResponseScript{}}
}

func (m *memScriptRepo) List(context.Context) ([]repository.ResponseScript, error) {
	out := []repository.ResponseScript{}
	for _, s := range m.byID {
		out = append(out, s)
	}
	return out, nil
}

func (m *memScriptRepo) GetByID(_ context.Context, id uuid.UUID) (*repository.ResponseScript, error) {
	s, ok := m.byID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return &s, nil
}

func (m *memScriptRepo) Create(_ context.Context, s *repository.ResponseScript) error {
	for _, e := range m.byID {
		if strings.EqualFold(e.Name, s.Name) {
			return repository.ErrScriptNameExists
		}
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	m.byID[s.ID] = *s
	return nil
}

func (m *memScriptRepo) Update(_ context.Context, s *repository.ResponseScript) error {
	if _, ok := m.byID[s.ID]; !ok {
		return repository.ErrNotFound
	}
	m.byID[s.ID] = *s
	return nil
}

func (m *memScriptRepo) Delete(_ context.Context, id uuid.UUID) error {
	if _, ok := m.byID[id]; !ok {
		return repository.ErrNotFound
	}
	delete(m.byID, id)
	return nil
}

func TestValidateScriptCmd(t *testing.T) {
	ok := []string{
		`ipconfig /all`,
		`powershell -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"`,
		`reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		`POWERSHELL.EXE -Command "Get-Service"`,
		`__EJECT_USB__`,
	}
	for _, c := range ok {
		if err := validateScriptCmd(c); err != nil {
			t.Errorf("expected %q to be valid, got %v", c, err)
		}
	}

	bad := map[string]string{
		"empty":            `   `,
		"not allowed exe":  `certutil -urlcache -f http://x/y.exe y.exe`,
		"path to exe":      `C:\Users\Public\powershell.exe -Command "whoami"`,
		"forward path":     `./cmd /C dir`,
		"ps -File":         `powershell -File C:\x.ps1`,
		"ps -f short":      `powershell -f C:\x.ps1`,
		"ps -enc":          `powershell -enc ZQBjAGgAbwA=`,
		"ps /EncodedCmd":   `powershell /EncodedCommand ZQBjAGgAbwA=`,
		"newline":          "ipconfig\nwhoami",
		"tab":              "ipconfig\t/all",
		"unbalanced quote": `powershell -Command "Get-Process`,
		"too long":         "ipconfig " + strings.Repeat("a", maxScriptCmdLen),
	}
	for name, c := range bad {
		if err := validateScriptCmd(c); err == nil {
			t.Errorf("%s: expected %q to be rejected", name, c)
		}
	}
}

func TestLibraryExecutablesMatchesAgentTier(t *testing.T) {
	// Guard against silent drift: the agent's playbookAllowedCommands has 22 entries.
	if got := len(libraryExecutables); got != 22 {
		t.Fatalf("libraryExecutables has %d entries; update it together with the agent's playbookAllowedCommands", got)
	}
}

// scriptTestServer returns handlers wired with a live registry and an
// in-memory script repo, plus a registered agent channel.
func scriptTestServer(t *testing.T) (*Handlers, *memScriptRepo, uuid.UUID, chan *edrv1.Command) {
	t.Helper()
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	h := &Handlers{logger: logger}
	reg := handlers.NewAgentRegistry(logger)
	h.SetRegistry(reg)
	repo := newMemScriptRepo()
	h.SetResponseScriptRepo(repo)
	agentID := uuid.New()
	ch := reg.Register(agentID.String())
	return h, repo, agentID, ch
}

func doJSON(t *testing.T, fn echo.HandlerFunc, method, path string, params map[string]string, body any, roles []string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, strings.NewReader(string(b)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e := echo.New()
	c := e.NewContext(req, rec)
	for k, v := range params {
		c.SetParamNames(k)
		c.SetParamValues(v)
	}
	c.Set(string(ContextKeyUser), &UserClaims{UserID: uuid.NewString(), Username: "tester", Roles: roles})
	if err := fn(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	return rec
}

func TestRunScriptUsesStoredCommandAtLibraryTier(t *testing.T) {
	h, repo, agentID, ch := scriptTestServer(t)
	script := &repository.ResponseScript{Name: "Top processes", Cmd: `powershell -Command "Get-Process"`, TimeoutSeconds: 120, Enabled: true}
	if err := repo.Create(context.Background(), script); err != nil {
		t.Fatal(err)
	}

	// The client tries to smuggle a different command type, cmd and tier.
	body := map[string]any{
		"script_id":    script.ID.String(),
		"command_type": "isolate_network",
		"parameters":   map[string]string{"cmd": "certutil evil", "authz_tier": "custom", "extra": "x"},
	}
	rec := doJSON(t, h.ExecuteAgentCommand, http.MethodPost, "/", map[string]string{"id": agentID.String()}, body, []string{"analyst"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}

	select {
	case cmd := <-ch:
		if cmd.Type != edrv1.CommandType(9) {
			t.Errorf("type = %v, want RUN_CMD (9)", cmd.Type)
		}
		want := map[string]string{"cmd": script.Cmd, "authz_tier": "library", "from_playbook": "true"}
		if len(cmd.Parameters) != len(want) {
			t.Errorf("parameters = %v, want exactly %v", cmd.Parameters, want)
		}
		for k, v := range want {
			if cmd.Parameters[k] != v {
				t.Errorf("param %s = %q, want %q", k, cmd.Parameters[k], v)
			}
		}
	default:
		t.Fatal("no command was dispatched to the agent")
	}
}

func TestRunScriptRejectsDisabledAndUnknown(t *testing.T) {
	h, repo, agentID, ch := scriptTestServer(t)
	disabled := &repository.ResponseScript{Name: "Off", Cmd: "ipconfig", TimeoutSeconds: 60, Enabled: false}
	_ = repo.Create(context.Background(), disabled)

	cases := map[string]struct {
		id   string
		want int
	}{
		"disabled": {disabled.ID.String(), http.StatusConflict},
		"unknown":  {uuid.NewString(), http.StatusNotFound},
		"invalid":  {"not-a-uuid", http.StatusBadRequest},
	}
	for name, tc := range cases {
		rec := doJSON(t, h.ExecuteAgentCommand, http.MethodPost, "/", map[string]string{"id": agentID.String()},
			map[string]any{"script_id": tc.id}, []string{"admin"})
		if rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d (%s)", name, rec.Code, tc.want, rec.Body.String())
		}
	}
	select {
	case cmd := <-ch:
		t.Fatalf("nothing should be dispatched, got %v", cmd)
	default:
	}
}

func TestClientCannotSelfGrantTier(t *testing.T) {
	// Regression guard for Stage 1: without script_id a client-supplied authz_tier is stripped.
	h, _, agentID, ch := scriptTestServer(t)
	body := map[string]any{
		"command_type": "run_cmd",
		"parameters":   map[string]string{"cmd": "ipconfig", "authz_tier": "library"},
	}
	rec := doJSON(t, h.ExecuteAgentCommand, http.MethodPost, "/", map[string]string{"id": agentID.String()}, body, []string{"analyst"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	cmd := <-ch
	if _, ok := cmd.Parameters["authz_tier"]; ok {
		t.Fatalf("client authz_tier was not stripped: %v", cmd.Parameters)
	}
}

func TestScriptCRUDRequiresAdmin(t *testing.T) {
	h, repo, _, _ := scriptTestServer(t)
	valid := map[string]any{"name": "Net config", "cmd": "ipconfig /all", "timeout_seconds": 60}

	rec := doJSON(t, h.CreateResponseScript, http.MethodPost, "/", nil, valid, []string{"analyst"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin create: status %d, want 403", rec.Code)
	}

	rec = doJSON(t, h.CreateResponseScript, http.MethodPost, "/", nil,
		map[string]any{"name": "Bad", "cmd": "certutil -urlcache"}, []string{"admin"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid cmd: status %d, want 400", rec.Code)
	}

	rec = doJSON(t, h.CreateResponseScript, http.MethodPost, "/", nil, valid, []string{"admin"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin create: status %d, body %s", rec.Code, rec.Body.String())
	}
	if len(repo.byID) != 1 {
		t.Fatalf("expected 1 stored script, got %d", len(repo.byID))
	}

	rec = doJSON(t, h.CreateResponseScript, http.MethodPost, "/", nil,
		map[string]any{"name": "NET CONFIG", "cmd": "ipconfig"}, []string{"admin"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate name: status %d, want 409", rec.Code)
	}

	var id uuid.UUID
	for k := range repo.byID {
		id = k
	}
	rec = doJSON(t, h.DeleteResponseScript, http.MethodDelete, "/", map[string]string{"id": id.String()}, nil, []string{"analyst"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin delete: status %d, want 403", rec.Code)
	}
	rec = doJSON(t, h.DeleteResponseScript, http.MethodDelete, "/", map[string]string{"id": id.String()}, nil, []string{"admin"})
	if rec.Code != http.StatusOK || len(repo.byID) != 0 {
		t.Fatalf("admin delete: status %d, remaining %d", rec.Code, len(repo.byID))
	}
}
