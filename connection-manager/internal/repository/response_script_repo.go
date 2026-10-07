package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrScriptNameExists is returned when a script name collides (case-insensitive).
var ErrScriptNameExists = errors.New("a script with this name already exists")

// ResponseScript is a stored run_cmd command line from the dashboard-managed
// script library (table response_scripts).
type ResponseScript struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Cmd            string    `json:"cmd"`
	TimeoutSeconds int       `json:"timeout_seconds"`
	Enabled        bool      `json:"enabled"`
	CreatedBy      string    `json:"created_by"`
	UpdatedBy      string    `json:"updated_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ResponseScriptRepository persists the response script library.
type ResponseScriptRepository interface {
	List(ctx context.Context) ([]ResponseScript, error)
	GetByID(ctx context.Context, id uuid.UUID) (*ResponseScript, error)
	Create(ctx context.Context, s *ResponseScript) error
	Update(ctx context.Context, s *ResponseScript) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// PostgresResponseScriptRepository implements ResponseScriptRepository.
type PostgresResponseScriptRepository struct {
	db *pgxpool.Pool
}

// NewPostgresResponseScriptRepository creates the repository.
func NewPostgresResponseScriptRepository(db *pgxpool.Pool) *PostgresResponseScriptRepository {
	return &PostgresResponseScriptRepository{db: db}
}

const responseScriptColumns = `id, name, description, cmd, timeout_seconds, enabled, created_by, updated_by, created_at, updated_at`

func scanResponseScript(row pgx.Row, s *ResponseScript) error {
	return row.Scan(&s.ID, &s.Name, &s.Description, &s.Cmd, &s.TimeoutSeconds, &s.Enabled,
		&s.CreatedBy, &s.UpdatedBy, &s.CreatedAt, &s.UpdatedAt)
}

func (r *PostgresResponseScriptRepository) List(ctx context.Context) ([]ResponseScript, error) {
	rows, err := r.db.Query(ctx, `SELECT `+responseScriptColumns+` FROM response_scripts ORDER BY LOWER(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResponseScript{}
	for rows.Next() {
		var s ResponseScript
		if err := scanResponseScript(rows, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *PostgresResponseScriptRepository) GetByID(ctx context.Context, id uuid.UUID) (*ResponseScript, error) {
	var s ResponseScript
	err := scanResponseScript(r.db.QueryRow(ctx, `SELECT `+responseScriptColumns+` FROM response_scripts WHERE id = $1`, id), &s)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *PostgresResponseScriptRepository) Create(ctx context.Context, s *ResponseScript) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	now := time.Now().UTC()
	s.CreatedAt, s.UpdatedAt = now, now
	_, err := r.db.Exec(ctx, `
		INSERT INTO response_scripts (`+responseScriptColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		s.ID, s.Name, s.Description, s.Cmd, s.TimeoutSeconds, s.Enabled, s.CreatedBy, s.UpdatedBy, s.CreatedAt, s.UpdatedAt)
	return mapScriptWriteErr(err)
}

func (r *PostgresResponseScriptRepository) Update(ctx context.Context, s *ResponseScript) error {
	s.UpdatedAt = time.Now().UTC()
	tag, err := r.db.Exec(ctx, `
		UPDATE response_scripts
		SET name = $1, description = $2, cmd = $3, timeout_seconds = $4, enabled = $5, updated_by = $6, updated_at = $7
		WHERE id = $8`,
		s.Name, s.Description, s.Cmd, s.TimeoutSeconds, s.Enabled, s.UpdatedBy, s.UpdatedAt, s.ID)
	if err != nil {
		return mapScriptWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *PostgresResponseScriptRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM response_scripts WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// mapScriptWriteErr converts a unique-name violation into ErrScriptNameExists.
func mapScriptWriteErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrScriptNameExists
	}
	return err
}
