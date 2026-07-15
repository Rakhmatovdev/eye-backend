package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type Service struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewService(db *pgxpool.Pool, log *zap.Logger) *Service {
	return &Service{db: db, log: log}
}

func (s *Service) Log(ctx context.Context, userID, action, resource, ip, result string) error {
	var lastHash string
	err := s.db.QueryRow(ctx, "SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1").Scan(&lastHash)
	if err != nil {
		lastHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	ts := time.Now().Format(time.RFC3339)
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%s", userID, action, resource, ip, result, ts)
	hasher := sha256.New()
	hasher.Write([]byte(data + lastHash))
	newHash := fmt.Sprintf("%x", hasher.Sum(nil))

	_, err = s.db.Exec(ctx,
		`INSERT INTO audit_logs (user_id, action, resource, ip, result, hash, prev_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		userID, action, resource, ip, result, newHash, lastHash)
	if err != nil {
		s.log.Error("Failed to write audit log", zap.Error(err))
	}
	return err
}

func (s *Service) List(ctx context.Context, search, action string) ([]*AuditLog, error) {
	query := `SELECT id, user_id, action, resource, ip, result, hash, prev_hash, ts 
	          FROM audit_logs WHERE ($1 = '' OR user_id ILIKE $1 OR action ILIKE $1)
	          ORDER BY ts DESC LIMIT 100`
	
	searchVal := ""
	if search != "" {
		searchVal = "%" + search + "%"
	}

	rows, err := s.db.Query(ctx, query, searchVal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		l := &AuditLog{}
		err = rows.Scan(&l.ID, &l.UserID, &l.Action, &l.Resource, &l.IP, &l.Result, &l.Hash, &l.PrevHash, &l.Timestamp)
		if err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}
