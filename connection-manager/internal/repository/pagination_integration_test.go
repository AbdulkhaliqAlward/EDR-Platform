package repository

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appdatabase "github.com/edr-platform/connection-manager/internal/database"
	"github.com/edr-platform/connection-manager/pkg/audit"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/shared/pagination"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func TestSecurityEventPagesPostgres(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	ddl, err := os.ReadFile(filepath.Join("..", "database", "migrations", "052_security_events.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(ddl)); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO security_events(id,event_type,severity,description,metadata,created_at) SELECT md5(n::text)::uuid,'login_failed','warning',repeat('detail-only',100),'{"proof":"complete metadata"}'::jsonb,$1 FROM generate_series(1,63)n`, stamp); err != nil {
		t.Fatal(err)
	}
	repo := audit.NewRepository(pool)
	for _, order := range []string{"asc", "desc"} {
		t.Run(order, func(t *testing.T) {
			q := url.Values{"order": {order}}
			load := func() pagination.Page[audit.Event] {
				p, err := pagination.Parse(q, pagination.Options{Scope: "security-test", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}})
				if err != nil {
					t.Fatal(err)
				}
				rows, err := repo.List(ctx, audit.SecurityEventFilter{Page: &p, Severity: "warning"})
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					if len(row.Description) > 256 || len(row.Metadata) > 0 {
						t.Fatal("heavy list data")
					}
				}
				return pagination.Build(rows, p, func(row audit.Event) pagination.Key { return pagination.TimeKey(row.CreatedAt, row.ID.String()) })
			}
			first := load()
			page := first
			seen := map[string]bool{}
			if _, err := pool.Exec(ctx, "INSERT INTO security_events(event_type,severity,created_at) VALUES('login_failed','warning',now()+interval '1 hour')"); err != nil {
				t.Fatal(err)
			}
			for {
				for _, row := range page.Data {
					key := row.ID.String()
					if seen[key] {
						t.Fatal("duplicate", key)
					}
					seen[key] = true
				}
				if !page.PageInfo.HasNext {
					break
				}
				q.Set("cursor", *page.PageInfo.NextCursor)
				page = load()
			}
			if len(seen) != 63 {
				t.Fatal("missing rows", len(seen))
			}
			for page.PageInfo.HasPrev {
				q.Set("cursor", *page.PageInfo.PrevCursor)
				page = load()
			}
			if fmt.Sprint(page.Data) != fmt.Sprint(first.Data) {
				t.Fatal("reverse mismatch")
			}
			detail, err := repo.GetByID(ctx, first.Data[0].ID)
			if err != nil || detail.Metadata["proof"] != "complete metadata" || len(detail.Description) != 1100 {
				t.Fatal("incomplete details", err)
			}
		})
	}
}

func TestPaginationMigrationUpgradeAndInvalidIndex(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	ddl, err := os.ReadFile(filepath.Join("..", "database", "migrations", "052_security_events.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(ddl)); err != nil {
		t.Fatal(err)
	}
	// Model an existing v63 installation in our disposable fixture. Historical
	// migrations are deliberately not replayed over existing data.
	if _, err := pool.Exec(ctx, "CREATE TABLE schema_migrations(version bigint NOT NULL PRIMARY KEY,dirty boolean NOT NULL); INSERT INTO schema_migrations VALUES(63,false)"); err != nil {
		t.Fatal(err)
	}
	conn := pool.Config().ConnConfig
	cfg := &appdatabase.PostgresConfig{Host: conn.Host, Port: int(conn.Port), User: conn.User, Password: conn.Password, Database: conn.Database, SSLMode: "disable"}
	for n := 0; n < 2; n++ {
		if err := appdatabase.RunMigrations(cfg, logrus.New()); err != nil {
			t.Fatal(err)
		}
	}
	var version int
	var dirty bool
	if err := pool.QueryRow(ctx, "SELECT version,dirty FROM schema_migrations").Scan(&version, &dirty); err != nil || version != 71 || dirty {
		t.Fatalf("version=%d dirty=%v err=%v", version, dirty, err)
	}
	agent := fixtureAgent(t, pool)
	if _, err := pool.Exec(ctx, "INSERT INTO commands(agent_id,command_type) VALUES($1,'collect_logs'),($1,'collect_logs')", agent); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DROP INDEX CONCURRENTLY idx_commands_page_issued_id"); err != nil {
		t.Fatal(err)
	}
	// A failed concurrent unique build leaves an INVALID index with the name.
	if _, err := pool.Exec(ctx, "CREATE UNIQUE INDEX CONCURRENTLY idx_commands_page_issued_id ON commands(status)"); err == nil {
		t.Fatal("fixture should fail uniqueness")
	}
	if err := appdatabase.RunMigrations(cfg, logrus.New()); err == nil || !strings.Contains(err.Error(), "missing or invalid") {
		t.Fatal("invalid index silently accepted", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE schema_migrations SET dirty=true"); err != nil {
		t.Fatal(err)
	}
	if err := appdatabase.RunMigrations(cfg, logrus.New()); err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatal("dirty migration silently skipped", err)
	}
}

func TestEventPagesPostgres(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	agent := fixtureAgent(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond).Add(123 * time.Microsecond)
	_, err := pool.Exec(ctx, `INSERT INTO events(id,agent_id,event_type,ts,created_at,raw)
 SELECT md5(n::text)::uuid,$1,'process',$2,$2,jsonb_build_object('pid',42,'payload',repeat('heavy',10000)) FROM generate_series(1,63) n`, agent, stamp)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewPostgresEventRepository(pool)
	for _, order := range []string{"asc", "desc"} {
		t.Run(order, func(t *testing.T) {
			q := url.Values{"limit": {"25"}, "order": {order}}
			opt := pagination.Options{Scope: "events-test", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}}
			load := func() pagination.Page[EventRow] {
				p, err := pagination.Parse(q, opt)
				if err != nil {
					t.Fatal(err)
				}
				rows, total, err := repo.Search(ctx, EventSearchRequest{Page: &p})
				if err != nil {
					t.Fatal(err)
				}
				if total != 0 {
					t.Fatal("default query requested a count")
				}
				for _, row := range rows {
					if strings.Contains(string(row.Raw), "heavy") {
						t.Fatal("heavy data in list")
					}
				}
				return pagination.Build(rows, p, func(e EventRow) pagination.Key { return pagination.TimeKey(e.CreatedAt, e.ID.String()) })
			}
			first := load()
			if len(first.Data) != 25 || !first.PageInfo.HasNext {
				t.Fatal("invalid first page")
			}
			// A source timestamp inside the range, ingested after the page's fence.
			_, err := pool.Exec(ctx, `INSERT INTO events(agent_id,event_type,ts,created_at) VALUES($1,'file',$2,now()+interval '1 hour')`, agent, stamp)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			page := first
			for {
				for _, row := range page.Data {
					key := row.ID.String()
					if seen[key] {
						t.Fatal("duplicate", key)
					}
					seen[key] = true
				}
				if !page.PageInfo.HasNext {
					break
				}
				q.Set("cursor", *page.PageInfo.NextCursor)
				page = load()
			}
			if len(seen) != 63 {
				t.Fatalf("missing rows: %d", len(seen))
			}
			for page.PageInfo.HasPrev {
				q.Set("cursor", *page.PageInfo.PrevCursor)
				page = load()
			}
			if fmt.Sprint(page.Data) != fmt.Sprint(first.Data) {
				t.Fatal("previous navigation changed first page")
			}
			full, err := repo.GetByID(ctx, first.Data[0].ID)
			if err != nil || !strings.Contains(string(full.Raw), "heavy") {
				t.Fatal("detail lost payload", err)
			}
		})
	}
}

func TestEventPaginationIndexMigrations(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	for _, name := range []string{"064_events_page_created", "065_events_page_agent"} {
		sql, err := os.ReadFile(filepath.Join("..", "database", "migrations", name+".up.sql"))
		if err != nil {
			t.Fatal(err)
		}
		for repeat := 0; repeat < 2; repeat++ {
			if _, err := pool.Exec(ctx, string(sql)); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	var valid int
	err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname IN ('idx_events_page_created_id','idx_events_page_agent_created_id') AND i.indisvalid AND i.indisready`).Scan(&valid)
	if err != nil || valid != 2 {
		t.Fatalf("valid indexes=%d err=%v", valid, err)
	}
}

func TestCommandPagesPostgres(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	agent := fixtureAgent(t, pool)
	if _, err := pool.Exec(ctx, "ALTER TABLE agents ADD COLUMN hostname text; ALTER TABLE users ADD COLUMN username text"); err != nil {
		t.Fatal(err)
	}
	repo := NewPostgresCommandRepository(pool)
	stamp := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	for n := 0; n < 63; n++ {
		if err := repo.Create(ctx, &models.Command{AgentID: agent, CommandType: "collect_logs", Priority: 5, Status: models.CommandStatusCompleted, IssuedAt: stamp, Parameters: map[string]any{"proof": "detail-only"}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, order := range []string{"asc", "desc"} {
		t.Run(order, func(t *testing.T) {
			q := url.Values{"order": {order}}
			load := func() pagination.Page[CommandListItem] {
				p, err := pagination.Parse(q, pagination.Options{Scope: "commands-test", DefaultSort: "issued_at", Sorts: CommandSortColumns})
				if err != nil {
					t.Fatal(err)
				}
				rows, total, err := repo.ListAll(ctx, CommandListFilter{Page: &p, AgentID: &agent})
				if err != nil {
					t.Fatal(err)
				}
				if total != 0 {
					t.Fatal("unexpected count")
				}
				for _, row := range rows {
					if len(row.Parameters) != 0 || len(row.Result) != 0 {
						t.Fatal("heavy list data")
					}
				}
				return pagination.Build(rows, p, func(row CommandListItem) pagination.Key { return pagination.TimeKey(row.IssuedAt, row.ID.String()) })
			}
			first := load()
			page := first
			seen := map[string]bool{}
			if err := repo.Create(ctx, &models.Command{AgentID: agent, CommandType: "collect_logs", Priority: 5, Status: models.CommandStatusPending, IssuedAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			for {
				for _, row := range page.Data {
					key := row.ID.String()
					if seen[key] {
						t.Fatal("duplicate", key)
					}
					seen[key] = true
				}
				if !page.PageInfo.HasNext {
					break
				}
				q.Set("cursor", *page.PageInfo.NextCursor)
				page = load()
			}
			if len(seen) != 63 {
				t.Fatal("missing rows", len(seen))
			}
			for page.PageInfo.HasPrev {
				q.Set("cursor", *page.PageInfo.PrevCursor)
				page = load()
			}
			if fmt.Sprint(page.Data) != fmt.Sprint(first.Data) {
				t.Fatal("reverse navigation mismatch")
			}
			detail, err := repo.GetByID(ctx, first.Data[0].ID)
			if err != nil || detail.Parameters["proof"] != "detail-only" {
				t.Fatal("missing full parameters", err)
			}
		})
	}
}

func TestAuditPagesPostgres(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	ddl, err := os.ReadFile(filepath.Join("..", "database", "migrations", "004_create_audit_logs.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	// This table does not exist in the newly created, disposable fixture database.
	if _, err = pool.Exec(ctx, string(ddl)); err != nil {
		t.Fatal(err)
	}
	details, err := os.ReadFile(filepath.Join("..", "database", "migrations", "070_audit_logs_details.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(details)); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO audit_logs(id,action,created_at,old_value) SELECT md5(n::text)::uuid,'login',now()-interval '1 hour',jsonb_build_object('payload',repeat('heavy',1000)) FROM generate_series(1,63)n`)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewPostgresAuditLogRepository(pool)
	q := url.Values{"limit": {"25"}}
	seen := map[string]bool{}
	var firstID string
	for {
		p, err := pagination.Parse(q, pagination.Options{Scope: "audit-test", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}})
		if err != nil {
			t.Fatal(err)
		}
		rows, err := repo.List(ctx, AuditLogFilter{Page: &p, Actions: []string{"login"}, Text: map[string]string{"oldVal": "heavy"}})
		if err != nil {
			t.Fatal(err)
		}
		page := pagination.Build(rows, p, func(a *models.AuditLog) pagination.Key { return pagination.TimeKey(a.Timestamp, a.ID.String()) })
		for _, row := range page.Data {
			key := row.ID.String()
			if seen[key] {
				t.Fatal("duplicate", key)
			}
			seen[key] = true
			if firstID == "" {
				firstID = key
				full, err := repo.GetByID(ctx, row.ID)
				if err != nil || len(full.OldValue) < 1000 {
					t.Fatal("full detail missing", err)
				}
			}
			if len(row.OldValue) > 300 {
				t.Fatal("heavy list value")
			}
		}
		if !page.PageInfo.HasNext {
			break
		}
		q.Set("cursor", *page.PageInfo.NextCursor)
	}
	if len(seen) != 63 {
		t.Fatalf("missing rows: %d", len(seen))
	}

	// Details (the handler's description of what happened) are stored,
	// returned by list and detail, and searchable as "Extra info".
	entry := models.NewAuditLog(uuid.Nil, "analyst", "playbook.run", "playbook_execution", uuid.New()).
		WithDetails("playbook Contain host run on agent WS-042")
	if err := repo.Create(ctx, entry); err != nil {
		t.Fatal(err)
	}
	full, err := repo.GetByID(ctx, entry.ID)
	if err != nil || full.Details != "playbook Contain host run on agent WS-042" {
		t.Fatalf("details not persisted: %v %+v", err, full)
	}
	p, err := pagination.Parse(url.Values{}, pagination.Options{Scope: "audit-test", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := repo.List(ctx, AuditLogFilter{Page: &p, Text: map[string]string{"extra": "WS-042"}})
	if err != nil || len(rows) != 1 || rows[0].Details != full.Details {
		t.Fatalf("details not searchable: %v %d", err, len(rows))
	}
}
