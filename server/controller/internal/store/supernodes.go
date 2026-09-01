package store

import (
	"context"
	"database/sql"
	"time"

	"meshlink/server/controller/internal/model"
)

// Supernode Registry（M1-2）：
//   - 数据结构从第一天支持多个 Supernode（Registry + Pool）；
//   - 第一版仅 priority + health 简单选择（Agent 侧按 priority 排序 + 独立熔断）；
//   - Supernode 进程启动/心跳时自注册；Controller 不转发任何明文 Overlay 数据。

const createSupernodesTable = `
CREATE TABLE IF NOT EXISTS supernodes (
    id        TEXT PRIMARY KEY,
    host      TEXT NOT NULL,
    port      INTEGER NOT NULL,
    priority  INTEGER NOT NULL DEFAULT 100,
    healthy   INTEGER NOT NULL DEFAULT 1,
    last_seen TEXT NOT NULL
);
`

// UpsertSupernode 注册/更新 Supernode（幂等，按 id）。
func (s *Store) UpsertSupernode(ctx context.Context, sn model.Supernode) error {
	healthy := 0
	if sn.Healthy {
		healthy = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO supernodes (id, host, port, priority, healthy, last_seen)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			host = excluded.host,
			port = excluded.port,
			priority = excluded.priority,
			healthy = excluded.healthy,
			last_seen = excluded.last_seen
	`, sn.ID, sn.Host, sn.Port, sn.Priority, healthy, sn.LastSeen.UTC().Format(time.RFC3339))
	return err
}

// Supernodes 列出全部 Supernode（按 priority 升序 = 数值越小越优先）。
func (s *Store) Supernodes(ctx context.Context) ([]model.Supernode, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, host, port, priority, healthy, last_seen
		FROM supernodes
		ORDER BY priority ASC, id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []model.Supernode{}
	for rows.Next() {
		var sn model.Supernode
		var healthy int
		var lastSeen string
		if err := rows.Scan(&sn.ID, &sn.Host, &sn.Port, &sn.Priority, &healthy, &lastSeen); err != nil {
			return nil, err
		}
		sn.Healthy = healthy != 0
		if t, err := time.Parse(time.RFC3339, lastSeen); err == nil {
			sn.LastSeen = t
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// TouchSupernode 心跳：更新 last_seen + 标记健康。
func (s *Store) TouchSupernode(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE supernodes SET healthy = 1, last_seen = ? WHERE id = ?
	`, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// MarkSupernodeDown 健康探测失败后标记不可用（后续探测恢复）。
func (s *Store) MarkSupernodeDown(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE supernodes SET healthy = 0 WHERE id = ?
	`, id)
	return err
}
