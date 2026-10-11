package repository

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/shared/pagination"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAgentPagesPostgres(t *testing.T) {
	base := responseTestDB(t)
	ctx := context.Background()
	// A separate schema lets us use real agent migrations without replacing the
	// minimal agent ancestor referenced by the response fixture's foreign keys.
	if _, err := base.Exec(ctx, "CREATE SCHEMA agent_pages"); err != nil {
		t.Fatal(err)
	}
	config := base.Config().Copy()
	config.ConnConfig.RuntimeParams["search_path"] = "agent_pages,public"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, name := range []string{"001_create_agents", "010_add_is_isolated_to_agents", "012_add_agent_telemetry", "027_add_hardware_id_to_agents", "034_add_sysmon_status_to_agents", "043_add_asset_criticality_and_priority_function"} {
		sql, err := os.ReadFile(filepath.Join("..", "database", "migrations", name+".up.sql"))
		if err != nil {
			t.Fatal(err)
		}
		ddl := string(sql)
		if strings.HasPrefix(name, "043_") {
			ddl = strings.Split(ddl, "-- Constrain criticality")[0]
		} // Only the agent columns; vulnerability subsystem is not this fixture.
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	_, err = pool.Exec(ctx, `INSERT INTO agents(id,hostname,status,os_type,created_at,metadata)
 SELECT md5(n::text)::uuid,'page-host-'||lpad(n::text,3,'0'),'online',CASE WHEN n<=63 THEN 'windows' ELSE 'linux' END,now(),jsonb_build_object('profile','default','payload',repeat('heavy',1000)) FROM generate_series(1,70) n`)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewPostgresAgentRepository(pool)
	osType, search := "windows", "page-host"
	for _, sort := range []string{"created_at", "hostname", "status", "last_seen", "health_score"} {
		t.Run(sort, func(t *testing.T) {
			q := url.Values{"sort": {sort}, "order": {"asc"}}
			load := func() pagination.Page[*models.Agent] {
				p, err := pagination.Parse(q, pagination.Options{Scope: "agents-test", Offset: true, DefaultSort: "created_at", Sorts: AgentSortColumns})
				if err != nil {
					t.Fatal(err)
				}
				f := AgentFilter{Page: &p, SortBy: p.Sort, SortOrder: p.Order, OSType: &osType, Search: &search}
				rows, err := repo.List(ctx, f)
				if err != nil {
					t.Fatal(err)
				}
				count, err := repo.Count(ctx, f)
				if err != nil || count != 63 {
					t.Fatalf("count=%d err=%v", count, err)
				}
				for _, row := range rows {
					if _, ok := row.Metadata["payload"]; ok {
						t.Fatal("heavy metadata in list")
					}
				}
				return pagination.BuildOffset(rows, p)
			}
			first := load()
			page := first
			seen := map[string]bool{}
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
			if !reflect.DeepEqual(page.Data, first.Data) {
				t.Fatal("reverse navigation mismatch")
			}
			detail, err := repo.GetByID(ctx, first.Data[0].ID)
			if err != nil || detail.Metadata["payload"] == "" {
				t.Fatal("missing full metadata", err)
			}
		})
	}
}

func TestAgentListAndCountFilters(t *testing.T) {
	status, os, search := "online", "windows", "host' OR true--"
	where, args := agentListWhere(AgentFilter{Status: &status, OSType: &os, Search: &search})
	if where != " WHERE 1=1 AND status = $1 AND os_type = $2 AND hostname ILIKE $3" || !reflect.DeepEqual(args, []interface{}{status, os, "%" + search + "%"}) {
		t.Fatalf("unbound or missing filters: %s %v", where, args)
	}
	where, args = agentListWhere(AgentFilter{OSType: &os, Search: &search})
	if where != " WHERE 1=1 AND status <> 'deleted' AND os_type = $1 AND hostname ILIKE $2" || len(args) != 2 {
		t.Fatal("default visibility/filter mismatch", where, args)
	}
}
