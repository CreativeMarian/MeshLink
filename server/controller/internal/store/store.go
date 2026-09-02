// SQLite 存储层（Controller MVP）：七表 schema + 事务化数据访问。
//
// 约束（用户 Controller MVP 规格）：
// - UNIQUE（code / credential_hash / (session_id, device_id) / (invite_id, joiner)）
// - 事务：join / 兑换 / 公钥绑定 均在事务内校验+写入
// - 外键：session_members / candidates 级联删除（expires cleanup 一并清理）
// - 结构保持可迁移 PostgreSQL（标准 SQL，无 SQLite 专有类型）

package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"meshlink/server/controller/internal/model"
)

// 哨兵错误（store 层；api 层映射为 JSON 错误码 + HTTP 状态）。
var (
	ErrDeviceNotFound       = errors.New("device not found")
	ErrDeviceKeyMismatch    = errors.New("device noise public key mismatch") // 禁止自动覆盖
	ErrCredentialNotFound   = errors.New("credential not found")
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionExpired       = errors.New("session expired")
	ErrSessionStateInvalid  = errors.New("session state invalid")
	ErrCodeTaken            = errors.New("quick code already taken") // preferred_code 被占用
	ErrNotMember            = errors.New("device is not a session member")
	ErrInviteNotFound       = errors.New("invite not found")
	ErrInviteTokenInvalid   = errors.New("invite token invalid")
	ErrInviteExpired        = errors.New("invite expired")
	ErrInviteExhausted      = errors.New("invite max uses exhausted")
	ErrInviteRedeemed       = errors.New("invite already redeemed by device")
	ErrOverlayPoolInvalid   = errors.New("overlay pool invalid")
	ErrOverlayPoolExhausted = errors.New("overlay pool exhausted") // active 会话占满地址池
	ErrFriendshipNotFound   = errors.New("friendship not found")
	ErrFriendshipExists     = errors.New("friendship already exists")
	ErrFriendshipState      = errors.New("friendship state invalid")
	ErrNotFriends           = errors.New("devices are not friends")
	ErrNotTarget            = errors.New("device is not the session target")
	ErrSelfConnect          = errors.New("cannot connect to self")
)

// Store SQLite 存储句柄（并发安全：database/sql 连接池 + WAL + busy_timeout）。
type Store struct {
	db      *sql.DB
	overlay overlayPool
}

// overlayPool Controller 侧 Overlay IPAM 地址池（规格六）。
// 池按 /24 切分给每个会话；成员 IP 在会话子网内顺序分配（数据库唯一约束兜底）。
type overlayPool struct {
	base uint32 // 池网络地址（已按掩码对齐）
	bits uint32 // 池前缀长度（如 16）
}

// subnetCount 池内可容纳的 /24 子网数。
func (p overlayPool) subnetCount() int {
	if p.bits >= 32 {
		return 0
	}
	return 1 << (model.OverlaySubnetPrefix - p.bits)
}

// subnetAt 第 i 个 /24 子网的网络地址（uint32）。
func (p overlayPool) subnetAt(i int) uint32 {
	return p.base + uint32(i)<<(32-model.OverlaySubnetPrefix)
}

// parseOverlayPool 解析池 CIDR（如 10.88.0.0/16），严格校验：
// 前缀 8..24、网络地址对齐、非 0.0.0.0/0（不做全局 VPN）。
func parseOverlayPool(cidr string) (overlayPool, error) {
	netStr, bitsStr, ok := strings.Cut(cidr, "/")
	if !ok {
		return overlayPool{}, fmt.Errorf("%w: %s", ErrOverlayPoolInvalid, cidr)
	}
	bits, err := strconv.Atoi(bitsStr)
	if err != nil || bits < 8 || bits > model.OverlaySubnetPrefix {
		return overlayPool{}, fmt.Errorf("%w: 前缀须在 8..%d", ErrOverlayPoolInvalid, model.OverlaySubnetPrefix)
	}
	ip := net.ParseIP(netStr).To4()
	if ip == nil {
		return overlayPool{}, fmt.Errorf("%w: 非法 IPv4", ErrOverlayPoolInvalid)
	}
	base := binary.BigEndian.Uint32(ip)
	mask := prefixMask(uint32(bits))
	if base&mask != base {
		return overlayPool{}, fmt.Errorf("%w: 网络地址未对齐", ErrOverlayPoolInvalid)
	}
	if base == 0 {
		return overlayPool{}, fmt.Errorf("%w: 禁止 0.0.0.0/0", ErrOverlayPoolInvalid)
	}
	return overlayPool{base: base, bits: uint32(bits)}, nil
}

func prefixMask(bits uint32) uint32 {
	if bits == 0 {
		return 0
	}
	return math.MaxUint32 << (32 - bits)
}

func ipToString(v uint32) string {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, v)
	return b.String()
}

const schema = `
CREATE TABLE IF NOT EXISTS devices (
    device_id         TEXT PRIMARY KEY,
    noise_public_key  TEXT NOT NULL CHECK (length(noise_public_key) = 64),
    device_name       TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at        TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_credentials (
    device_id        TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    credential_hash  TEXT NOT NULL UNIQUE,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connection_sessions (
    session_id        TEXT PRIMARY KEY,
    code              TEXT NOT NULL UNIQUE CHECK (length(code) = 6),
    creator_device_id TEXT NOT NULL REFERENCES devices(device_id),
    target_device_id  TEXT REFERENCES devices(device_id),
    network_id        TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'WAITING',
    created_at        TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    overlay_subnet    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON connection_sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON connection_sessions(expires_at);
-- active 会话间 overlay 子网互斥（部分唯一：空串 = 尚未分配，仅迁移过渡）
CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_overlay
    ON connection_sessions(overlay_subnet) WHERE overlay_subnet != '';

CREATE TABLE IF NOT EXISTS session_members (
    session_id        TEXT NOT NULL REFERENCES connection_sessions(session_id) ON DELETE CASCADE,
    device_id         TEXT NOT NULL REFERENCES devices(device_id),
    role              TEXT NOT NULL CHECK (role IN ('creator','joiner')),
    noise_public_key  TEXT NOT NULL,
    joined_at         TEXT NOT NULL,
    overlay_ip        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (session_id, device_id)
);
-- 会话内 overlay IP 唯一（IPAM 分配 + 数据库层冲突检测双保险）
CREATE UNIQUE INDEX IF NOT EXISTS idx_members_overlay_ip
    ON session_members(session_id, overlay_ip) WHERE overlay_ip != '';

CREATE TABLE IF NOT EXISTS session_candidates (
    session_id        TEXT NOT NULL REFERENCES connection_sessions(session_id) ON DELETE CASCADE,
    device_id         TEXT NOT NULL REFERENCES devices(device_id),
    candidates        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (session_id, device_id)
);

CREATE TABLE IF NOT EXISTS friend_invites (
    invite_id         TEXT PRIMARY KEY,
    invite_token_hash TEXT NOT NULL,
    creator_device_id TEXT NOT NULL REFERENCES devices(device_id),
    network_id        TEXT NOT NULL,
    expires_at        TEXT,
    max_uses          INTEGER NOT NULL DEFAULT 0,
    used_count        INTEGER NOT NULL DEFAULT 0,
    status            TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invite_redemptions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    invite_id         TEXT NOT NULL REFERENCES friend_invites(invite_id) ON DELETE CASCADE,
    joiner_device_id  TEXT NOT NULL REFERENCES devices(device_id),
    redeemed_at       TEXT NOT NULL,
    friendship_id     TEXT NOT NULL,
    UNIQUE (invite_id, joiner_device_id)
);

CREATE TABLE IF NOT EXISTS friendships (
    friendship_id TEXT PRIMARY KEY,
    device_a      TEXT NOT NULL REFERENCES devices(device_id),
    device_b      TEXT NOT NULL REFERENCES devices(device_id),
    pair_key      TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL DEFAULT 'PENDING',
    created_at    TEXT NOT NULL,
    revoked_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_friendships_a ON friendships(device_a, status);
CREATE INDEX IF NOT EXISTS idx_friendships_b ON friendships(device_b, status);

-- M1-1.5：最近连接历史（本地视角，与好友关系分离；remote_fingerprint 快照来自
-- Registry，upsert 时由 store 从 devices 表读取，不信任客户端自报）。
CREATE TABLE IF NOT EXISTS recent_connections (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    local_device_id     TEXT NOT NULL REFERENCES devices(device_id),
    remote_device_id    TEXT NOT NULL REFERENCES devices(device_id),
    remote_name         TEXT NOT NULL DEFAULT '',
    remote_fingerprint  TEXT NOT NULL DEFAULT '',
    last_connected_at   TEXT NOT NULL,
    last_overlay_ip     TEXT NOT NULL DEFAULT '',
    last_path           TEXT NOT NULL DEFAULT '',
    connection_count    INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL,
    UNIQUE (local_device_id, remote_device_id)
);
CREATE INDEX IF NOT EXISTS idx_recent_local
    ON recent_connections(local_device_id, last_connected_at);
`

// Open 打开（或创建）数据库并执行迁移，overlay 地址池用默认值
// （model.OverlayPoolDefault = 10.88.0.0/16）。dsn 为文件路径；":memory:" 测试。
func Open(dsn string) (*Store, error) {
	return OpenWithOverlayPool(dsn, model.OverlayPoolDefault)
}

// OpenWithOverlayPool 同 Open，但 overlay 地址池由配置指定
// （规格六：地址池通过配置定义，例如 `-overlay-pool 172.31.0.0/16`）。
func OpenWithOverlayPool(dsn string, poolCidr string) (*Store, error) {
	pool, err := parseOverlayPool(poolCidr)
	if err != nil {
		return nil, err
	}
	isMemory := dsn == ":memory:" // P2-4：内存库跳过磁盘文件完整性校验
	// 单写连接：modernc/sqlite 并发写会 BUSY，靠 busy_timeout + 串行写事务；
	// 读并发不受限。文件库开启 WAL 提高读写并发。
	if !isMemory {
		dsn = "file:" + dsn + "?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	} else {
		dsn = "file::memory:?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// 内存库必须在同一连接上建表（多连接 = 多个独立内存库）。
	if isMemory {
		db.SetMaxOpenConns(1)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	// M1-2：Supernode Registry 表（独立追加，兼容旧库文件）。
	if _, err := db.Exec(createSupernodesTable); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate supernodes schema: %w", err)
	}
	if err := migrateColumns(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate columns: %w", err)
	}
	// P2-4：启动完整性校验——controller.db 损坏/被截断时（历史 502/controller 反复
	// 退出期间可能产生），sqlite 懒连接可能静默重建空库，导致设备身份/会话数据"凭空
	// 消失"。quick_check 快速校验，损坏则明确报错（含 db 路径），不再静默吞掉。
	if !isMemory {
		var check string
		if err := db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
			db.Close()
			return nil, fmt.Errorf("controller.db 完整性校验失败（文件损坏?）: check=%q path=%s", check, dsn)
		}
	}
	return &Store{db: db, overlay: pool}, nil
}

// migrateColumns 旧库文件轻量迁移（CREATE TABLE IF NOT EXISTS 不会补列）：
// 缺 overlay_subnet / overlay_ip 列时 ALTER 补齐（默认 ”，仅过渡）。
func migrateColumns(db *sql.DB) error {
	need := map[string]string{
		"connection_sessions": "target_device_id",
		"session_members":     "overlay_ip",
	}
	for table, column := range need {
		rows, err := db.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			return err
		}
		has := false
		for rows.Next() {
			var cid int
			var name, typ string
			var dflt sql.NullString
			var notNull, pk int
			if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
				rows.Close()
				return err
			}
			if name == column {
				has = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if !has {
			ddl := "TEXT NOT NULL DEFAULT ''"
			if column == "target_device_id" {
				// 6 位码会话无 target：可空（NULL 不触发外键校验）。
				ddl = "TEXT REFERENCES devices(device_id)"
			}
			if _, err := db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + ddl); err != nil {
				return fmt.Errorf("add %s.%s: %w", table, column, err)
			}
		}
	}
	return nil
}

// Close 关闭底层连接池。
func (s *Store) Close() error { return s.db.Close() }

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func parseTime(str string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, str)
}

// ---- 设备注册 / 公钥绑定 ----

// RegisterDevice 注册设备（首次）或校验既有绑定（幂等重放）。
//
// 公钥绑定规则（硬性）：
//   - device_id 不存在 → 建立绑定（device_id + noise_public_key + credential hash）；
//   - 已存在且公钥相同 → 允许（幂等），credential 不再下发；
//   - 已存在且公钥不同 → ErrDeviceKeyMismatch，绝不自动覆盖——需要显式
//     key rotation / 重新注册流程（MVP 不提供，防 MITM 换钥）。
//
// 返回 (device, created)：created=false 表示已注册（幂等命中）。
func (s *Store) RegisterDevice(ctx context.Context, deviceID, publicKeyHex, deviceName, credentialHash string) (model.Device, bool, error) {
	var dev model.Device
	created := false
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var storedKey, storedName, status string
		var createdAt, lastSeen string
		err := tx.QueryRowContext(ctx,
			`SELECT noise_public_key, device_name, status, created_at, last_seen_at
			 FROM devices WHERE device_id = ?`, deviceID,
		).Scan(&storedKey, &storedName, &status, &createdAt, &lastSeen)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// 首次注册：原子建立绑定。
			now := time.Now().UTC()
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO devices (device_id, noise_public_key, device_name, status, created_at, last_seen_at)
				 VALUES (?,?,?,?,?,?)`,
				deviceID, publicKeyHex, deviceName, string(model.DeviceActive), fmtTime(now), fmtTime(now),
			); err != nil {
				return fmt.Errorf("insert device: %w", err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO device_credentials (device_id, credential_hash, created_at) VALUES (?,?,?)`,
				deviceID, credentialHash, fmtTime(now),
			); err != nil {
				return fmt.Errorf("insert credential: %w", err)
			}
			created = true
			dev = model.Device{
				DeviceID: deviceID, NoisePublicKey: publicKeyHex, DeviceName: deviceName,
				Status: model.DeviceActive, CreatedAt: now, LastSeenAt: now,
			}
			return nil
		case err != nil:
			return fmt.Errorf("query device: %w", err)
		}
		// 已注册：公钥相同 → 幂等允许；不同 → KEY_MISMATCH（禁止覆盖）。
		if !strings.EqualFold(storedKey, publicKeyHex) {
			return ErrDeviceKeyMismatch
		}
		ct, _ := parseTime(createdAt)
		ls, _ := parseTime(lastSeen)
		dev = model.Device{
			DeviceID: deviceID, NoisePublicKey: storedKey, DeviceName: storedName,
			Status: model.DeviceStatus(status), CreatedAt: ct, LastSeenAt: ls,
		}
		_, err = tx.ExecContext(ctx, `UPDATE devices SET last_seen_at = ? WHERE device_id = ?`,
			fmtTime(time.Now().UTC()), deviceID)
		return err
	})
	if err != nil {
		return model.Device{}, false, err
	}
	return dev, created, nil
}

// DeviceByCredential 用 credential hash 查找设备（bearer 认证路径）。
// hash 相同 + 设备 ACTIVE 才通过。
func (s *Store) DeviceByCredential(ctx context.Context, credentialHash string) (model.Device, error) {
	var dev model.Device
	var createdAt, lastSeen string
	err := s.db.QueryRowContext(ctx, `
		SELECT d.device_id, d.noise_public_key, d.device_name, d.status, d.created_at, d.last_seen_at
		FROM devices d JOIN device_credentials c ON c.device_id = d.device_id
		WHERE c.credential_hash = ?`, credentialHash,
	).Scan(&dev.DeviceID, &dev.NoisePublicKey, &dev.DeviceName, &dev.Status, &createdAt, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Device{}, ErrCredentialNotFound
	}
	if err != nil {
		return model.Device{}, fmt.Errorf("query by credential: %w", err)
	}
	if dev.Status != model.DeviceActive {
		return model.Device{}, fmt.Errorf("%w: status=%s", ErrCredentialNotFound, dev.Status)
	}
	dev.CreatedAt, _ = parseTime(createdAt)
	dev.LastSeenAt, _ = parseTime(lastSeen)
	return dev, nil
}

// TouchDevice 刷新 last_seen（认证成功后调用，尽力而为）。
func (s *Store) TouchDevice(ctx context.Context, deviceID string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE devices SET last_seen_at = ? WHERE device_id = ?`,
		fmtTime(time.Now().UTC()), deviceID)
}

// ---- 6 位码连接会话 ----

// CreateSession 原子分配 6 位码并创建 WAITING 会话（10 分钟默认有效）。
// 唯一性靠 UNIQUE(code) + 事务内冲突重试；过期会话行在分配前清理以复用码空间。
func (s *Store) CreateSession(ctx context.Context, creatorDeviceID, networkID string, ttl time.Duration) (model.ConnectionSession, error) {
	return s.CreateSessionPreferred(ctx, creatorDeviceID, networkID, ttl, "")
}

// CreateSessionPreferred 创建 6 位码会话；preferred 非空时尝试使用该指定码
// （固定宽度字符串，前导零如 "001234" 必须完整保留——用户规格十）。
// 指定码被占用返回 ErrCodeTaken（不静默替换为随机码）。
func (s *Store) CreateSessionPreferred(ctx context.Context, creatorDeviceID, networkID string, ttl time.Duration, preferred string) (model.ConnectionSession, error) {
	if ttl <= 0 {
		ttl = model.SessionTTLDefault
	}
	var sess model.ConnectionSession
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		sess, err = createSessionInTx(ctx, tx, s.overlay, creatorDeviceID, networkID, ttl, preferred)
		return err
	})
	if err != nil {
		return model.ConnectionSession{}, err
	}
	return sess, nil
}

// JoinSession joiner 凭 6 位码加入会话（事务内状态校验 + 成员写入）。
//
// 返回的会话含 creator 公钥快照成员集——**joiner 获得 creator 公钥的唯一可信
// 来源是 Controller 注册表**（Session Code 不再承载公钥信任）。
func (s *Store) JoinSession(ctx context.Context, code, joinerDeviceID string) (model.ConnectionSession, []model.SessionMember, error) {
	var sess model.ConnectionSession
	var members []model.SessionMember
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var status, createdAt, expiresAt, overlaySubnet string
		err := tx.QueryRowContext(ctx, `
			SELECT session_id, code, creator_device_id, network_id, status, created_at, expires_at, overlay_subnet
			FROM connection_sessions WHERE code = ?`, code,
		).Scan(&sess.SessionID, &sess.Code, &sess.CreatorDeviceID, &sess.NetworkID, &status, &createdAt, &expiresAt, &overlaySubnet)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSessionNotFound
		}
		if err != nil {
			return fmt.Errorf("query session: %w", err)
		}
		sess.Status = model.SessionStatus(status)
		sess.CreatedAt, _ = parseTime(createdAt)
		sess.ExpiresAt, _ = parseTime(expiresAt)
		sess.OverlaySubnet = overlaySubnet

		if time.Now().UTC().After(sess.ExpiresAt) {
			return ErrSessionExpired
		}
		if sess.Status != model.SessionWaiting {
			return fmt.Errorf("%w: status=%s", ErrSessionStateInvalid, sess.Status)
		}
		if sess.CreatorDeviceID == joinerDeviceID {
			return fmt.Errorf("%w: creator cannot join own session", ErrSessionStateInvalid)
		}

		// joiner 公钥快照。
		var joinerPub string
		err = tx.QueryRowContext(ctx,
			`SELECT noise_public_key FROM devices WHERE device_id = ?`, joinerDeviceID,
		).Scan(&joinerPub)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceNotFound
		}
		if err != nil {
			return fmt.Errorf("query joiner: %w", err)
		}
		// joiner 在会话子网内分到下一个主机地址（Controller IPAM，非硬编码）。
		joinerIP, err := allocateMemberOverlayIP(ctx, tx, sess.SessionID, sess.OverlaySubnet)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO session_members (session_id, device_id, role, noise_public_key, joined_at, overlay_ip)
			VALUES (?,?,?,?,?,?)`,
			sess.SessionID, joinerDeviceID, string(model.RoleJoiner), joinerPub,
			fmtTime(time.Now().UTC()), joinerIP); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: already joined", ErrSessionStateInvalid)
			}
			return fmt.Errorf("insert joiner member: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE connection_sessions SET status = ? WHERE session_id = ?`,
			string(model.SessionJoined), sess.SessionID); err != nil {
			return fmt.Errorf("mark joined: %w", err)
		}
		sess.Status = model.SessionJoined

		members, err = queryMembers(ctx, tx, sess.SessionID)
		return err
	})
	if err != nil {
		return model.ConnectionSession{}, nil, err
	}
	return sess, members, nil
}

// Session 按 session_id 查会话（不修改状态；过期时返回 ErrSessionExpired）。
func (s *Store) Session(ctx context.Context, sessionID string) (model.ConnectionSession, error) {
	var sess model.ConnectionSession
	var status, createdAt, expiresAt, overlaySubnet string
	err := s.db.QueryRowContext(ctx, `
		SELECT session_id, code, creator_device_id, network_id, status, created_at, expires_at, overlay_subnet
		FROM connection_sessions WHERE session_id = ?`, sessionID,
	).Scan(&sess.SessionID, &sess.Code, &sess.CreatorDeviceID, &sess.NetworkID, &status, &createdAt, &expiresAt, &overlaySubnet)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ConnectionSession{}, ErrSessionNotFound
	}
	if err != nil {
		return model.ConnectionSession{}, fmt.Errorf("query session: %w", err)
	}
	sess.Status = model.SessionStatus(status)
	sess.CreatedAt, _ = parseTime(createdAt)
	sess.ExpiresAt, _ = parseTime(expiresAt)
	sess.OverlaySubnet = overlaySubnet
	if time.Now().UTC().After(sess.ExpiresAt) {
		return sess, ErrSessionExpired
	}
	return sess, nil
}

// Members 会话成员（含公钥快照）。
func (s *Store) Members(ctx context.Context, sessionID string) ([]model.SessionMember, error) {
	return queryMembers(ctx, s.db, sessionID)
}

func queryMembers(ctx context.Context, q queryer, sessionID string) ([]model.SessionMember, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT session_id, device_id, role, noise_public_key, joined_at, overlay_ip
		FROM session_members WHERE session_id = ? ORDER BY joined_at`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("query members: %w", err)
	}
	defer rows.Close()
	var out []model.SessionMember
	for rows.Next() {
		var m model.SessionMember
		var role, joinedAt string
		if err := rows.Scan(&m.SessionID, &m.DeviceID, &role, &m.NoisePublicKey, &joinedAt, &m.OverlayIP); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		m.Role = model.MemberRole(role)
		m.JoinedAt, _ = parseTime(joinedAt)
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---- 候选交换 ----

// PutCandidates 成员上传本端候选集（UPSERT），返回对端候选（若已上传）。
func (s *Store) PutCandidates(ctx context.Context, sessionID, deviceID string, cands []model.Candidate) error {
	blob, err := encodeCandidates(cands)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO session_candidates (session_id, device_id, candidates, updated_at)
		VALUES (?,?,?,?)
		ON CONFLICT(session_id, device_id) DO UPDATE SET candidates = excluded.candidates, updated_at = excluded.updated_at`,
		sessionID, deviceID, blob, fmtTime(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("put candidates: %w", err)
	}
	return nil
}

// Candidates 读取某成员候选集。
func (s *Store) Candidates(ctx context.Context, sessionID, deviceID string) ([]model.Candidate, time.Time, error) {
	var blob, updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT candidates, updated_at FROM session_candidates
		WHERE session_id = ? AND device_id = ?`, sessionID, deviceID,
	).Scan(&blob, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, ErrNotMember
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("query candidates: %w", err)
	}
	cands, err := decodeCandidates(blob)
	if err != nil {
		return nil, time.Time{}, err
	}
	ts, _ := parseTime(updatedAt)
	return cands, ts, nil
}

// ---- 好友邀请 ----

// CreateInvite 创建好友邀请（token hash 入库；明文 token 只在响应出现一次）。
func (s *Store) CreateInvite(ctx context.Context, creatorDeviceID, networkID, tokenHash string, expiresAt *time.Time, maxUses int64) (model.FriendInvite, error) {
	inv := model.FriendInvite{
		InviteID:        newID("inv"),
		InviteTokenHash: tokenHash,
		CreatorDeviceID: creatorDeviceID,
		NetworkID:       networkID,
		ExpiresAt:       expiresAt,
		MaxUses:         maxUses,
		Status:          model.InviteActive,
		CreatedAt:       time.Now().UTC(),
	}
	var exp any
	if expiresAt != nil {
		exp = fmtTime(*expiresAt)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO friend_invites (invite_id, invite_token_hash, creator_device_id, network_id, expires_at, max_uses, used_count, status, created_at)
		VALUES (?,?,?,?,?,?,0,?,?)`,
		inv.InviteID, inv.InviteTokenHash, inv.CreatorDeviceID, inv.NetworkID, exp, inv.MaxUses, string(inv.Status), fmtTime(inv.CreatedAt))
	if err != nil {
		return model.FriendInvite{}, fmt.Errorf("insert invite: %w", err)
	}
	return inv, nil
}

// Invite 查询邀请（不含 token hash）。
func (s *Store) Invite(ctx context.Context, inviteID string) (model.FriendInvite, error) {
	var inv model.FriendInvite
	var status, createdAt string
	var expires sql.NullString
	var tokenHash string
	err := s.db.QueryRowContext(ctx, `
		SELECT invite_id, invite_token_hash, creator_device_id, network_id, expires_at, max_uses, used_count, status, created_at
		FROM friend_invites WHERE invite_id = ?`, inviteID,
	).Scan(&inv.InviteID, &tokenHash, &inv.CreatorDeviceID, &inv.NetworkID, &expires, &inv.MaxUses, &inv.UsedCount, &status, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.FriendInvite{}, ErrInviteNotFound
	}
	if err != nil {
		return model.FriendInvite{}, fmt.Errorf("query invite: %w", err)
	}
	inv.Status = model.InviteStatus(status)
	inv.CreatedAt, _ = parseTime(createdAt)
	if expires.Valid && expires.String != "" {
		t, err := parseTime(expires.String)
		if err == nil {
			inv.ExpiresAt = &t
		}
	}
	return inv, nil
}

// InviteTokenHash 校验用途：读取 token hash（比对邀请码）。
func (s *Store) InviteTokenHash(ctx context.Context, inviteID string) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT invite_token_hash FROM friend_invites WHERE invite_id = ?`, inviteID,
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInviteNotFound
	}
	return hash, err
}

// RedeemInvite 兑换好友邀请（M1-1 语义）：事务内校验 token hash / 有效期 /
// 次数 / 重复兑换，通过则建立一条 **PENDING 好友关系**（不再创建连接会话——
// 好友关系与 Online Session 分离，规格三/七）。邀请方 = device_a，兑换方 = device_b。
//
// 返回 (friendship, creatorDeviceID, err)。creatorDeviceID 供 api 层发布
// friend_added 事件通知邀请方。
func (s *Store) RedeemInvite(ctx context.Context, inviteID, tokenHash, joinerDeviceID string) (model.Friendship, string, error) {
	storedHash, err := s.InviteTokenHash(ctx, inviteID)
	if err != nil {
		return model.Friendship{}, "", err
	}
	if !constantTimeEqualHex(storedHash, tokenHash) {
		return model.Friendship{}, "", ErrInviteTokenInvalid
	}

	var fs model.Friendship
	var creator string
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		var status string
		var expires sql.NullString
		var usedCount, maxUses int64
		var invCreator, invNetwork string
		if err := tx.QueryRowContext(ctx, `
			SELECT status, expires_at, max_uses, used_count, creator_device_id, network_id
			FROM friend_invites WHERE invite_id = ?`, inviteID,
		).Scan(&status, &expires, &maxUses, &usedCount, &invCreator, &invNetwork); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrInviteNotFound
			}
			return fmt.Errorf("query invite: %w", err)
		}
		if model.InviteStatus(status) != model.InviteActive {
			return fmt.Errorf("%w: status=%s", ErrInviteExhausted, status)
		}
		if expires.Valid && expires.String != "" {
			exp, _ := parseTime(expires.String)
			if time.Now().UTC().After(exp) {
				return ErrInviteExpired
			}
		}
		if maxUses > 0 && usedCount >= maxUses {
			return ErrInviteExhausted
		}
		if invCreator == joinerDeviceID {
			return fmt.Errorf("%w: creator cannot redeem own invite", ErrInviteTokenInvalid)
		}

		// 已存在好友关系（任何状态）→ 拒绝（FRIENDSHIP_EXISTS，双向均防）。
		var existingID string
		perr := tx.QueryRowContext(ctx,
			`SELECT friendship_id FROM friendships WHERE pair_key = ?`,
			pairKey(invCreator, joinerDeviceID)).Scan(&existingID)
		switch {
		case perr == nil:
			return ErrFriendshipExists
		case !errors.Is(perr, sql.ErrNoRows):
			return fmt.Errorf("query friendship: %w", perr)
		}

		// 建立 PENDING 好友关系（pair_key 规范化防反向重复）。
		fs, err = insertFriendship(ctx, tx, invCreator, joinerDeviceID, model.FriendshipPending)
		if err != nil {
			return err
		}
		creator = invCreator
		// 兑换记录（关联 friendship_id）。
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO invite_redemptions (invite_id, joiner_device_id, redeemed_at, friendship_id)
			VALUES (?,?,?,?)`,
			inviteID, joinerDeviceID, fmtTime(time.Now().UTC()), fs.FriendshipID); err != nil {
			if isUniqueViolation(err) {
				return ErrInviteRedeemed
			}
			return fmt.Errorf("insert redemption: %w", err)
		}
		// 次数推进 + 状态联动（max_uses 达到 → EXHAUSTED）。
		newUsed := usedCount + 1
		newStatus := model.InviteActive
		if maxUses > 0 && newUsed >= maxUses {
			newStatus = model.InviteExhausted
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE friend_invites SET used_count = ?, status = ? WHERE invite_id = ?`,
			newUsed, string(newStatus), inviteID); err != nil {
			return fmt.Errorf("update invite: %w", err)
		}
		return nil
	})
	if err != nil {
		return model.Friendship{}, "", err
	}
	return fs, creator, nil
}

// ---- 好友关系 ----

// insertFriendship 事务内建立好友关系（pair_key = 规范化双端键，防反向重复）。
func insertFriendship(ctx context.Context, tx *sql.Tx, deviceA, deviceB string, status model.FriendshipStatus) (model.Friendship, error) {
	if deviceA == deviceB {
		return model.Friendship{}, ErrSelfConnect
	}
	pair := pairKey(deviceA, deviceB)
	var existing string
	err := tx.QueryRowContext(ctx,
		`SELECT friendship_id FROM friendships WHERE pair_key = ?`, pair).Scan(&existing)
	switch {
	case err == nil:
		return model.Friendship{}, fmt.Errorf("%w: pair=%s", ErrFriendshipExists, pair)
	case !errors.Is(err, sql.ErrNoRows):
		return model.Friendship{}, fmt.Errorf("query friendship: %w", err)
	}
	fs := model.Friendship{
		FriendshipID: newID("fr"),
		DeviceA:      deviceA,
		DeviceB:      deviceB,
		PairKey:      pair,
		Status:       status,
		CreatedAt:    time.Now().UTC(),
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO friendships (friendship_id, device_a, device_b, pair_key, status, created_at, revoked_at)
		VALUES (?,?,?,?,?,?,NULL)`,
		fs.FriendshipID, fs.DeviceA, fs.DeviceB, fs.PairKey, string(fs.Status), fmtTime(fs.CreatedAt)); err != nil {
		if isUniqueViolation(err) {
			return model.Friendship{}, fmt.Errorf("%w: pair=%s", ErrFriendshipExists, pair)
		}
		return model.Friendship{}, fmt.Errorf("insert friendship: %w", err)
	}
	return fs, nil
}

func pairKey(a, b string) string {
	if a < b {
		return a + "\x1f" + b
	}
	return b + "\x1f" + a
}

// Friendship 查询单条好友关系。
func (s *Store) Friendship(ctx context.Context, friendshipID string) (model.Friendship, error) {
	var fs model.Friendship
	var status, createdAt string
	var revoked sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT friendship_id, device_a, device_b, status, created_at, revoked_at
		FROM friendships WHERE friendship_id = ?`, friendshipID,
	).Scan(&fs.FriendshipID, &fs.DeviceA, &fs.DeviceB, &status, &createdAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Friendship{}, ErrFriendshipNotFound
	}
	if err != nil {
		return model.Friendship{}, fmt.Errorf("query friendship: %w", err)
	}
	fs.Status = model.FriendshipStatus(status)
	fs.CreatedAt, _ = parseTime(createdAt)
	if revoked.Valid && revoked.String != "" {
		t, _ := parseTime(revoked.String)
		fs.RevokedAt = &t
	}
	return fs, nil
}

// FriendshipsForDevice 某设备参与的（非 REMOVED 的）好友关系列表。
func (s *Store) FriendshipsForDevice(ctx context.Context, deviceID string) ([]model.Friendship, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT friendship_id, device_a, device_b, status, created_at, revoked_at
		FROM friendships
		WHERE (device_a = ? OR device_b = ?) AND status != ?
		ORDER BY created_at DESC`, deviceID, deviceID, string(model.FriendshipRemoved))
	if err != nil {
		return nil, fmt.Errorf("query friendships: %w", err)
	}
	defer rows.Close()
	var out []model.Friendship
	for rows.Next() {
		var fs model.Friendship
		var status, createdAt string
		var revoked sql.NullString
		if err := rows.Scan(&fs.FriendshipID, &fs.DeviceA, &fs.DeviceB, &status, &createdAt, &revoked); err != nil {
			return nil, fmt.Errorf("scan friendship: %w", err)
		}
		fs.Status = model.FriendshipStatus(status)
		fs.CreatedAt, _ = parseTime(createdAt)
		if revoked.Valid && revoked.String != "" {
			t, _ := parseTime(revoked.String)
			fs.RevokedAt = &t
		}
		out = append(out, fs)
	}
	return out, rows.Err()
}

// SetFriendshipStatus 变更好友关系状态（accept → ACCEPTED；reject/revoke → REMOVED + revoked_at）。
// deviceID 必须是关系成员。返回更新后的关系。
func (s *Store) SetFriendshipStatus(ctx context.Context, friendshipID, deviceID string, status model.FriendshipStatus) (model.Friendship, error) {
	var fs model.Friendship
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var a, b, cur string
		var revoked sql.NullString
		err := tx.QueryRowContext(ctx, `
			SELECT device_a, device_b, status, revoked_at FROM friendships WHERE friendship_id = ?`,
			friendshipID,
		).Scan(&a, &b, &cur, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFriendshipNotFound
		}
		if err != nil {
			return fmt.Errorf("query friendship: %w", err)
		}
		if deviceID != a && deviceID != b {
			return ErrNotMember
		}
		if status == model.FriendshipAccepted && cur != string(model.FriendshipPending) {
			return fmt.Errorf("%w: status=%s（仅 PENDING 可接受）", ErrFriendshipState, cur)
		}
		var revokedVal any
		if status == model.FriendshipRemoved || status == model.FriendshipBlocked {
			revokedVal = fmtTime(time.Now().UTC())
		} else if revoked.Valid && revoked.String != "" {
			revokedVal = revoked.String
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE friendships SET status = ?, revoked_at = ? WHERE friendship_id = ?`,
			string(status), revokedVal, friendshipID); err != nil {
			return fmt.Errorf("update friendship: %w", err)
		}
		fs, err = queryFriendshipTx(ctx, tx, friendshipID)
		return err
	})
	if err != nil {
		return model.Friendship{}, err
	}
	return fs, nil
}

func queryFriendshipTx(ctx context.Context, tx *sql.Tx, friendshipID string) (model.Friendship, error) {
	var fs model.Friendship
	var status, createdAt string
	var revoked sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT friendship_id, device_a, device_b, status, created_at, revoked_at
		FROM friendships WHERE friendship_id = ?`, friendshipID,
	).Scan(&fs.FriendshipID, &fs.DeviceA, &fs.DeviceB, &status, &createdAt, &revoked)
	if err != nil {
		return model.Friendship{}, err
	}
	fs.Status = model.FriendshipStatus(status)
	fs.CreatedAt, _ = parseTime(createdAt)
	if revoked.Valid && revoked.String != "" {
		t, _ := parseTime(revoked.String)
		fs.RevokedAt = &t
	}
	return fs, nil
}

// AreFriends 判断两端是否存在 ACCEPTED 好友关系。
func (s *Store) AreFriends(ctx context.Context, deviceA, deviceB string) (bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `
		SELECT friendship_id FROM friendships
		WHERE pair_key = ? AND status = ?`,
		pairKey(deviceA, deviceB), string(model.FriendshipAccepted),
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query friendship: %w", err)
	}
	return true, nil
}

// areFriendsTx 事务内判断 ACCEPTED 好友关系（供 withTx 内部使用；避免在
// 事务内走连接池查询造成单连接死锁）。
func areFriendsTx(ctx context.Context, tx *sql.Tx, deviceA, deviceB string) (bool, error) {
	var id string
	err := tx.QueryRowContext(ctx, `
		SELECT friendship_id FROM friendships
		WHERE pair_key = ? AND status = ?`,
		pairKey(deviceA, deviceB), string(model.FriendshipAccepted),
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query friendship: %w", err)
	}
	return true, nil
}

// ---- M1-1.5：最近连接历史 ----

// UpsertRecentConnection 记录/更新一条最近连接（6 位码临时连接成功后由 Agent 调用）。
// 对端名称与指纹快照必须来自 Controller Device Registry（devices 表）——函数内部
// 读取，绝不信任调用方传入的指纹；已存在则累加 connection_count 并刷新最新连接信息。
func (s *Store) UpsertRecentConnection(ctx context.Context, localDeviceID, remoteDeviceID, overlayIP, path string) (model.RecentConnection, error) {
	var rc model.RecentConnection
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		// 对端必须已注册：指纹/名称只从 Registry 取。
		var name, pubKey string
		err := tx.QueryRowContext(ctx,
			`SELECT device_name, noise_public_key FROM devices WHERE device_id = ?`, remoteDeviceID,
		).Scan(&name, &pubKey)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceNotFound
		}
		if err != nil {
			return fmt.Errorf("query remote device: %w", err)
		}
		now := time.Now().UTC()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO recent_connections
				(local_device_id, remote_device_id, remote_name, remote_fingerprint,
				 last_connected_at, last_overlay_ip, last_path, connection_count, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
			ON CONFLICT(local_device_id, remote_device_id) DO UPDATE SET
				remote_name        = excluded.remote_name,
				remote_fingerprint = excluded.remote_fingerprint,
				last_connected_at  = excluded.last_connected_at,
				last_overlay_ip    = excluded.last_overlay_ip,
				last_path          = excluded.last_path,
				connection_count   = recent_connections.connection_count + 1`,
			localDeviceID, remoteDeviceID, name, pubKey,
			fmtTime(now), overlayIP, path, fmtTime(now),
		); err != nil {
			return fmt.Errorf("upsert recent_connection: %w", err)
		}
		rc, err = queryRecentTx(ctx, tx, localDeviceID, remoteDeviceID)
		return err
	})
	if err != nil {
		return model.RecentConnection{}, err
	}
	return rc, nil
}

// ListRecentConnections 某设备的最近连接历史（按最近连接时间倒序）。
func (s *Store) ListRecentConnections(ctx context.Context, localDeviceID string) ([]model.RecentConnection, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, local_device_id, remote_device_id, remote_name, remote_fingerprint,
		       last_connected_at, last_overlay_ip, last_path, connection_count, created_at
		FROM recent_connections WHERE local_device_id = ?
		ORDER BY last_connected_at DESC`, localDeviceID)
	if err != nil {
		return nil, fmt.Errorf("query recent connections: %w", err)
	}
	defer rows.Close()
	var out []model.RecentConnection
	for rows.Next() {
		var rc model.RecentConnection
		var lastAt, createdAt string
		if err := rows.Scan(&rc.ID, &rc.LocalDeviceID, &rc.RemoteDeviceID, &rc.RemoteName,
			&rc.RemoteFingerprint, &lastAt, &rc.LastOverlayIP, &rc.LastPath,
			&rc.ConnectionCount, &createdAt); err != nil {
			return nil, fmt.Errorf("scan recent connection: %w", err)
		}
		rc.LastConnectedAt, _ = parseTime(lastAt)
		rc.CreatedAt, _ = parseTime(createdAt)
		out = append(out, rc)
	}
	return out, rows.Err()
}

// DeleteRecentConnection 删除一条本地最近连接记录（只影响本地历史，不影响好友关系）。
func (s *Store) DeleteRecentConnection(ctx context.Context, localDeviceID, remoteDeviceID string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM recent_connections WHERE local_device_id = ? AND remote_device_id = ?`,
		localDeviceID, remoteDeviceID); err != nil {
		return fmt.Errorf("delete recent connection: %w", err)
	}
	return nil
}

func queryRecentTx(ctx context.Context, tx *sql.Tx, localDeviceID, remoteDeviceID string) (model.RecentConnection, error) {
	var rc model.RecentConnection
	var lastAt, createdAt string
	err := tx.QueryRowContext(ctx, `
		SELECT id, local_device_id, remote_device_id, remote_name, remote_fingerprint,
		       last_connected_at, last_overlay_ip, last_path, connection_count, created_at
		FROM recent_connections WHERE local_device_id = ? AND remote_device_id = ?`,
		localDeviceID, remoteDeviceID,
	).Scan(&rc.ID, &rc.LocalDeviceID, &rc.RemoteDeviceID, &rc.RemoteName,
		&rc.RemoteFingerprint, &lastAt, &rc.LastOverlayIP, &rc.LastPath,
		&rc.ConnectionCount, &createdAt)
	if err != nil {
		return model.RecentConnection{}, err
	}
	rc.LastConnectedAt, _ = parseTime(lastAt)
	rc.CreatedAt, _ = parseTime(createdAt)
	return rc, nil
}

// FriendViews 某设备的好友列表（对端设备 + 在线状态）。
func (s *Store) FriendViews(ctx context.Context, deviceID string) ([]model.FriendView, error) {
	friendships, err := s.FriendshipsForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	out := make([]model.FriendView, 0, len(friendships))
	for _, fs := range friendships {
		peerID := fs.DeviceB
		if peerID == deviceID {
			peerID = fs.DeviceA
		}
		peer, err := s.DeviceWithPresence(ctx, peerID)
		if err != nil {
			continue // 对端设备已不存在：跳过（不应发生，级联保证）
		}
		out = append(out, model.FriendView{
			FriendshipID: fs.FriendshipID,
			Status:       fs.Status,
			CreatedAt:    fs.CreatedAt,
			Peer:         peer,
		})
	}
	return out, nil
}

// DeviceWithPresence 设备 + 在线判定。
func (s *Store) DeviceWithPresence(ctx context.Context, deviceID string) (model.DeviceWithPresence, error) {
	dev, err := s.Device(ctx, deviceID)
	if err != nil {
		return model.DeviceWithPresence{}, err
	}
	return model.DeviceWithPresence{Device: dev, Online: isOnline(dev.LastSeenAt)}, nil
}

func isOnline(lastSeen time.Time) bool {
	return time.Now().UTC().Sub(lastSeen) <= model.PresenceOnlineWindow
}

// Device 查询设备详情。
func (s *Store) Device(ctx context.Context, deviceID string) (model.Device, error) {
	var dev model.Device
	var createdAt, lastSeen string
	err := s.db.QueryRowContext(ctx, `
		SELECT device_id, noise_public_key, device_name, status, created_at, last_seen_at
		FROM devices WHERE device_id = ?`, deviceID,
	).Scan(&dev.DeviceID, &dev.NoisePublicKey, &dev.DeviceName, &dev.Status, &createdAt, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Device{}, ErrDeviceNotFound
	}
	if err != nil {
		return model.Device{}, fmt.Errorf("query device: %w", err)
	}
	dev.CreatedAt, _ = parseTime(createdAt)
	dev.LastSeenAt, _ = parseTime(lastSeen)
	return dev, nil
}

// InvitesForDevice 邀请方名下的邀请列表。
func (s *Store) InvitesForDevice(ctx context.Context, creatorDeviceID string) ([]model.FriendInvite, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT invite_id, creator_device_id, network_id, expires_at, max_uses, used_count, status, created_at
		FROM friend_invites WHERE creator_device_id = ? ORDER BY created_at DESC`, creatorDeviceID)
	if err != nil {
		return nil, fmt.Errorf("query invites: %w", err)
	}
	defer rows.Close()
	var out []model.FriendInvite
	for rows.Next() {
		var inv model.FriendInvite
		var status, createdAt string
		var expires sql.NullString
		if err := rows.Scan(&inv.InviteID, &inv.CreatorDeviceID, &inv.NetworkID, &expires, &inv.MaxUses, &inv.UsedCount, &status, &createdAt); err != nil {
			return nil, fmt.Errorf("scan invite: %w", err)
		}
		inv.Status = model.InviteStatus(status)
		inv.CreatedAt, _ = parseTime(createdAt)
		if expires.Valid && expires.String != "" {
			t, _ := parseTime(expires.String)
			inv.ExpiresAt = &t
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RevokeInvite 撤销邀请（status → REVOKED；仅邀请方可撤销；撤销后不可再兑换）。
func (s *Store) RevokeInvite(ctx context.Context, inviteID, creatorDeviceID string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE friend_invites SET status = ? WHERE invite_id = ? AND creator_device_id = ? AND status = ?`,
		string(model.InviteRevoked), inviteID, creatorDeviceID, string(model.InviteActive))
	if err != nil {
		return fmt.Errorf("revoke invite: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// 可能是非创建者 / 已非 ACTIVE。
		if _, err := s.Invite(ctx, inviteID); err != nil {
			return err
		}
		return fmt.Errorf("%w: invite 非 ACTIVE 或非创建者", ErrInviteNotFound)
	}
	return nil
}

// ---- 好友快速连接（连接请求信令） ----

// CreateFriendSession 为好友直连创建 WAITING 会话（target_device_id 指定对端）。
// 与 6 位码会话同构（仍分配唯一 code 但仅作标识）；target 接受后才 JOINED。
// 前置校验：两端必须是 ACCEPTED 好友（否则 ErrNotFriends）。
func (s *Store) CreateFriendSession(ctx context.Context, creatorDeviceID, targetDeviceID, networkID string) (model.ConnectionSession, error) {
	if creatorDeviceID == targetDeviceID {
		return model.ConnectionSession{}, ErrSelfConnect
	}
	friends, err := s.AreFriends(ctx, creatorDeviceID, targetDeviceID)
	if err != nil {
		return model.ConnectionSession{}, err
	}
	if !friends {
		return model.ConnectionSession{}, ErrNotFriends
	}
	var sess model.ConnectionSession
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		sess, err = createSessionInTx(ctx, tx, s.overlay, creatorDeviceID, networkID, model.SessionTTLDefault, "", targetDeviceID)
		return err
	})
	if err != nil {
		return model.ConnectionSession{}, err
	}
	return sess, nil
}

// AcceptConnectionRequest 目标设备接受好友直连请求：校验 target 身份 + 仍是
// 好友 → 作为 joiner 写入成员（overlay IP 分配），会话 JOINED。
func (s *Store) AcceptConnectionRequest(ctx context.Context, sessionID, targetDeviceID string) (model.ConnectionSession, []model.SessionMember, error) {
	var sess model.ConnectionSession
	var members []model.SessionMember
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var status, createdAt, expiresAt, overlaySubnet, target string
		err := tx.QueryRowContext(ctx, `
			SELECT session_id, code, creator_device_id, target_device_id, network_id, status, created_at, expires_at, overlay_subnet
			FROM connection_sessions WHERE session_id = ?`, sessionID,
		).Scan(&sess.SessionID, &sess.Code, &sess.CreatorDeviceID, &target, &sess.NetworkID, &status, &createdAt, &expiresAt, &overlaySubnet)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSessionNotFound
		}
		if err != nil {
			return fmt.Errorf("query session: %w", err)
		}
		sess.Status = model.SessionStatus(status)
		sess.CreatedAt, _ = parseTime(createdAt)
		sess.ExpiresAt, _ = parseTime(expiresAt)
		sess.OverlaySubnet = overlaySubnet
		if target == "" {
			return fmt.Errorf("%w: 非好友直连会话", ErrNotTarget)
		}
		if target != targetDeviceID {
			return ErrNotTarget
		}
		if time.Now().UTC().After(sess.ExpiresAt) {
			return ErrSessionExpired
		}
		if sess.Status != model.SessionWaiting {
			return fmt.Errorf("%w: status=%s", ErrSessionStateInvalid, sess.Status)
		}
		// 仍是 ACCEPTED 好友（防好友已删除后接受请求）。
		friends, err := areFriendsTx(ctx, tx, sess.CreatorDeviceID, targetDeviceID)
		if err != nil {
			return err
		}
		if !friends {
			return ErrNotFriends
		}
		var targetPub string
		err = tx.QueryRowContext(ctx,
			`SELECT noise_public_key FROM devices WHERE device_id = ?`, targetDeviceID,
		).Scan(&targetPub)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceNotFound
		}
		if err != nil {
			return fmt.Errorf("query target: %w", err)
		}
		targetIP, err := allocateMemberOverlayIP(ctx, tx, sess.SessionID, sess.OverlaySubnet)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO session_members (session_id, device_id, role, noise_public_key, joined_at, overlay_ip)
			VALUES (?,?,?,?,?,?)`,
			sess.SessionID, targetDeviceID, string(model.RoleJoiner), targetPub, fmtTime(time.Now().UTC()), targetIP); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: already accepted", ErrSessionStateInvalid)
			}
			return fmt.Errorf("insert target member: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE connection_sessions SET status = ? WHERE session_id = ?`,
			string(model.SessionJoined), sess.SessionID); err != nil {
			return fmt.Errorf("mark joined: %w", err)
		}
		sess.Status = model.SessionJoined
		members, err = queryMembers(ctx, tx, sess.SessionID)
		return err
	})
	if err != nil {
		return model.ConnectionSession{}, nil, err
	}
	return sess, members, nil
}

// RejectConnectionRequest 目标设备拒绝好友直连请求（会话 CLOSED）。
func (s *Store) RejectConnectionRequest(ctx context.Context, sessionID, targetDeviceID string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var status, target string
		err := tx.QueryRowContext(ctx,
			`SELECT status, target_device_id FROM connection_sessions WHERE session_id = ?`, sessionID,
		).Scan(&status, &target)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSessionNotFound
		}
		if err != nil {
			return fmt.Errorf("query session: %w", err)
		}
		if target == "" || target != targetDeviceID {
			return ErrNotTarget
		}
		if model.SessionStatus(status) != model.SessionWaiting {
			return fmt.Errorf("%w: status=%s", ErrSessionStateInvalid, status)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE connection_sessions SET status = ? WHERE session_id = ?`,
			string(model.SessionClosed), sessionID); err != nil {
			return fmt.Errorf("reject session: %w", err)
		}
		return nil
	})
}

// SessionTarget 会话目标设备（好友直连）校验 + 查询（供事件发布与状态查询）。
func (s *Store) SessionTarget(ctx context.Context, sessionID string) (creator, target string, status string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT creator_device_id, target_device_id, status FROM connection_sessions WHERE session_id = ?`,
		sessionID,
	).Scan(&creator, &target, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", ErrSessionNotFound
	}
	return creator, target, status, err
}

// CloseFriendSessions 好友撤销/删除后关闭双方之间全部活跃好友直连会话。
// 返回被关闭的 session_id 列表（供事件发布 FRIEND_AUTH_REVOKED 通知）。
func (s *Store) CloseFriendSessions(ctx context.Context, deviceA, deviceB string) ([]string, error) {
	var ids []string
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT session_id FROM connection_sessions
			WHERE status = ? AND (
				(creator_device_id = ? AND target_device_id = ?) OR
				(creator_device_id = ? AND target_device_id = ?)
			)`, string(model.SessionWaiting), deviceA, deviceB, deviceB, deviceA)
		if err != nil {
			return fmt.Errorf("query friend sessions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx,
				`UPDATE connection_sessions SET status = ? WHERE session_id = ?`,
				string(model.SessionClosed), id); err != nil {
				return fmt.Errorf("close session %s: %w", id, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// InviteRedemptions 邀请兑换记录列表（关联 friendship_id；邀请方据此发现新好友）。
func (s *Store) InviteRedemptions(ctx context.Context, inviteID string) ([]model.InviteRedemption, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT invite_id, joiner_device_id, redeemed_at, friendship_id
		FROM invite_redemptions WHERE invite_id = ? ORDER BY redeemed_at`, inviteID)
	if err != nil {
		return nil, fmt.Errorf("query redemptions: %w", err)
	}
	defer rows.Close()
	var out []model.InviteRedemption
	for rows.Next() {
		var rd model.InviteRedemption
		var redeemedAt string
		if err := rows.Scan(&rd.InviteID, &rd.JoinerDeviceID, &redeemedAt, &rd.FriendshipID); err != nil {
			return nil, fmt.Errorf("scan redemption: %w", err)
		}
		rd.RedeemedAt, _ = parseTime(redeemedAt)
		out = append(out, rd)
	}
	return out, rows.Err()
}

// ---- 清理 ----

// CleanupExpired 删除过期会话（级联 members/candidates）与过期邀请。
// 返回删除行数。CreateSession 分配码前会增量清理；此函数供后台周期任务。
func (s *Store) CleanupExpired(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM connection_sessions WHERE expires_at <= ?`, fmtTime(time.Now().UTC()))
	if err != nil {
		return 0, fmt.Errorf("cleanup sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	res, err = s.db.ExecContext(ctx,
		`UPDATE friend_invites SET status = ? WHERE expires_at IS NOT NULL AND expires_at <= ? AND status = ?`,
		string(model.InviteRevoked), fmtTime(time.Now().UTC()), string(model.InviteActive))
	if err != nil {
		return n, fmt.Errorf("cleanup invites: %w", err)
	}
	m, _ := res.RowsAffected()
	return n + m, nil
}

// ---- 内部 ----

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (s *Store) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed") && strings.Contains(msg, "unique")
}

func createSessionInTx(ctx context.Context, tx *sql.Tx, pool overlayPool, creatorDeviceID, networkID string, ttl time.Duration, preferred string, targetDeviceID ...string) (model.ConnectionSession, error) {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM connection_sessions WHERE expires_at <= ?`, fmtTime(time.Now().UTC())); err != nil {
		return model.ConnectionSession{}, fmt.Errorf("purge expired: %w", err)
	}
	target := ""
	if len(targetDeviceID) > 0 {
		target = targetDeviceID[0]
	}
	// 6 位码会话 target 为 NULL（NULL 不触发外键校验）。
	var targetVal any
	if target != "" {
		targetVal = target
	}
	// Overlay IPAM：事务内选第一个未被 active 会话占用的 /24（过期行已清理，
	// 子网随行删除回收；并发安全靠事务串行 + 部分唯一索引兜底）。
	subnetStr, err := allocateOverlaySubnet(ctx, tx, pool)
	if err != nil {
		return model.ConnectionSession{}, err
	}
	now := time.Now().UTC()
	for attempt := 0; attempt < 16; attempt++ {
		var code string
		if attempt == 0 && preferred != "" {
			code = preferred
		} else {
			code, err = codeGen()
			if err != nil {
				return model.ConnectionSession{}, err
			}
		}
		sess := model.ConnectionSession{
			SessionID:       newID("sess"),
			Code:            code,
			CreatorDeviceID: creatorDeviceID,
			NetworkID:       networkID,
			Status:          model.SessionWaiting,
			CreatedAt:       now,
			ExpiresAt:       now.Add(ttl),
			OverlaySubnet:   subnetStr,
		}
		var pubKey string
		err = tx.QueryRowContext(ctx,
			`SELECT noise_public_key FROM devices WHERE device_id = ?`, creatorDeviceID,
		).Scan(&pubKey)
		if errors.Is(err, sql.ErrNoRows) {
			return model.ConnectionSession{}, ErrDeviceNotFound
		}
		if err != nil {
			return model.ConnectionSession{}, fmt.Errorf("query creator: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO connection_sessions (session_id, code, creator_device_id, target_device_id, network_id, status, created_at, expires_at, overlay_subnet)
			VALUES (?,?,?,?,?,?,?,?,?)`,
			sess.SessionID, sess.Code, sess.CreatorDeviceID, targetVal, sess.NetworkID,
			string(sess.Status), fmtTime(sess.CreatedAt), fmtTime(sess.ExpiresAt), sess.OverlaySubnet)
		if err != nil {
			if isUniqueViolation(err) {
				if attempt == 0 && preferred != "" {
					// 指定码被占用：不静默替换（用户规格十：冲突检测）。
					return model.ConnectionSession{}, fmt.Errorf("%w: %s", ErrCodeTaken, preferred)
				}
				continue
			}
			return model.ConnectionSession{}, fmt.Errorf("insert session: %w", err)
		}
		// creator 拿到会话子网内第 1 个主机地址（.1）；后续成员顺序分配。
		creatorIP, err := allocateMemberOverlayIP(ctx, tx, sess.SessionID, subnetStr)
		if err != nil {
			return model.ConnectionSession{}, err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO session_members (session_id, device_id, role, noise_public_key, joined_at, overlay_ip)
			VALUES (?,?,?,?,?,?)`,
			sess.SessionID, creatorDeviceID, string(model.RoleCreator), pubKey, fmtTime(sess.CreatedAt), creatorIP)
		if err != nil {
			return model.ConnectionSession{}, fmt.Errorf("insert creator member: %w", err)
		}
		return sess, nil
	}
	return model.ConnectionSession{}, errors.New("code allocation exhausted")
}

// allocateOverlaySubnet 事务内从池中取第一个未被占用（且有效期内）的 /24。
// 冲突检测 = 查询占用集合 + 部分唯一索引（idx_sessions_overlay）兜底。
func allocateOverlaySubnet(ctx context.Context, tx *sql.Tx, pool overlayPool) (string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT overlay_subnet FROM connection_sessions WHERE overlay_subnet != ''`)
	if err != nil {
		return "", fmt.Errorf("query overlay subnets: %w", err)
	}
	used := map[string]bool{}
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			rows.Close()
			return "", fmt.Errorf("scan overlay subnet: %w", err)
		}
		used[sub] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	for i := 0; i < pool.subnetCount(); i++ {
		sub := fmt.Sprintf("%s/%d", ipToString(pool.subnetAt(i)), model.OverlaySubnetPrefix)
		if !used[sub] {
			return sub, nil
		}
	}
	return "", ErrOverlayPoolExhausted
}

// allocateMemberOverlayIP 事务内为本会话新成员分配子网内最小未用主机地址
// （从 .1 开始；网络地址 .0 与广播 .255 保留）。UNIQUE 索引兜底冲突。
func allocateMemberOverlayIP(ctx context.Context, tx *sql.Tx, sessionID, subnetCidr string) (string, error) {
	netStr, _, ok := strings.Cut(subnetCidr, "/")
	if !ok {
		return "", fmt.Errorf("invalid subnet %q", subnetCidr)
	}
	ip := net.ParseIP(netStr).To4()
	if ip == nil {
		return "", fmt.Errorf("invalid subnet ip %q", subnetCidr)
	}
	base := binary.BigEndian.Uint32(ip)

	rows, err := tx.QueryContext(ctx,
		`SELECT overlay_ip FROM session_members WHERE session_id = ? AND overlay_ip != ''`, sessionID)
	if err != nil {
		return "", fmt.Errorf("query member ips: %w", err)
	}
	used := map[uint32]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return "", fmt.Errorf("scan member ip: %w", err)
		}
		if v := net.ParseIP(s).To4(); v != nil {
			used[binary.BigEndian.Uint32(v)] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	for host := uint32(1); host < 255; host++ {
		if !used[base+host] {
			return ipToString(base + host), nil
		}
	}
	return "", fmt.Errorf("%w: session %s subnet %s", ErrOverlayPoolExhausted, sessionID, subnetCidr)
}
