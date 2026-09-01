// Controller 领域模型（Controller MVP）。
//
// 硬性规则：
// - Controller 是身份信任根：device_id → noise_static_public_key 绑定，
//   公钥不可静默覆盖（DEVICE_KEY_MISMATCH）。
// - 6 位连接码只负责 Session Lookup，绝不作为认证 secret、绝不参与
//   Noise 密钥派生。
// - Controller 只做 Identity / Signaling / Session / Invite / Candidate，
//   禁止进入数据面（不做文件转发 / Overlay relay / UDP relay）。

package model

import "time"

// DeviceStatus 设备注册状态。
type DeviceStatus string

const (
	DeviceActive   DeviceStatus = "ACTIVE"
	DeviceRevoked  DeviceStatus = "REVOKED"
	DeviceRotating DeviceStatus = "ROTATING"
)

// SessionStatus 连接会话状态机：WAITING --join--> JOINED --close--> CLOSED。
type SessionStatus string

const (
	SessionWaiting SessionStatus = "WAITING"
	SessionJoined  SessionStatus = "JOINED"
	SessionClosed  SessionStatus = "CLOSED"
)

// MemberRole 会话成员角色（与 Noise 角色一致：creator=responder，joiner=initiator）。
type MemberRole string

const (
	RoleCreator MemberRole = "creator"
	RoleJoiner  MemberRole = "joiner"
)

// InviteStatus 好友邀请状态。
type InviteStatus string

const (
	InviteActive    InviteStatus = "ACTIVE"
	InviteRevoked   InviteStatus = "REVOKED"
	InviteExhausted InviteStatus = "EXHAUSTED"
)

// FriendshipStatus 好友关系状态（M1-1）：PENDING --accept--> ACCEPTED；删除/拒绝 → REMOVED。
type FriendshipStatus string

const (
	FriendshipPending  FriendshipStatus = "PENDING"
	FriendshipAccepted FriendshipStatus = "ACCEPTED"
	FriendshipBlocked  FriendshipStatus = "BLOCKED"
	FriendshipRemoved  FriendshipStatus = "REMOVED"
)

// Device 已注册设备（身份信任根条目）。
type Device struct {
	DeviceID       string       `json:"device_id"`
	NoisePublicKey string       `json:"noise_public_key"` // hex 64
	DeviceName     string       `json:"device_name,omitempty"`
	Status         DeviceStatus `json:"status"`
	CreatedAt      time.Time    `json:"created_at"`
	LastSeenAt     time.Time    `json:"last_seen_at"`
}

// DeviceWithPresence 设备 + 在线状态（M1-1 设备列表 / 好友页展示）。
type DeviceWithPresence struct {
	Device
	// Online 由 last_seen_at 新鲜度判定（最近一次心跳/请求在在线窗口内）。
	Online bool `json:"online"`
}

// Friendship 好友关系（M1-1；建立在 Device Identity 之上）。
// device_a = 邀请创建方，device_b = 兑换方；pair_key 为规范化（排序后）双端
// 键，防止同对设备反向重复建友。
type Friendship struct {
	FriendshipID string           `json:"friendship_id"`
	DeviceA      string           `json:"device_a"`
	DeviceB      string           `json:"device_b"`
	PairKey      string           `json:"-"`
	Status       FriendshipStatus `json:"status"`
	CreatedAt    time.Time        `json:"created_at"`
	RevokedAt    *time.Time       `json:"revoked_at,omitempty"`
}

// FriendView 好友列表项（对端设备 + 在线状态 + 关系状态）。
type FriendView struct {
	FriendshipID string            `json:"friendship_id"`
	Status       FriendshipStatus  `json:"status"`
	CreatedAt    time.Time         `json:"created_at"`
	Peer         DeviceWithPresence `json:"peer"`
}

// InviteView 邀请列表项（含状态与使用情况，token 绝不外发）。
type InviteView struct {
	InviteID        string       `json:"invite_id"`
	NetworkID       string       `json:"network_id"`
	ExpiresAt       *time.Time   `json:"expires_at,omitempty"` // nil = 永久
	MaxUses         int64        `json:"max_uses"`
	UsedCount       int64        `json:"used_count"`
	Status          InviteStatus `json:"status"`
	CreatedAt       time.Time    `json:"created_at"`
	Redemptions     []InviteRedemption `json:"redemptions,omitempty"`
}

// RecentConnection 最近连接历史（M1-1.5；临时 6 位码连接产生的本地历史，与好友关系分离）。
// 隐私要求：只保存必要显示信息，不保存公网 IP / 完整 candidate / STUN 信息（高级诊断另存）。
// remote_fingerprint 必须来自 Controller Device Registry 的设备注册公钥快照——由
// Controller 从 devices 表读取后落库，客户端不可自报、不可信任客户端传入的指纹。
type RecentConnection struct {
	ID                int64     `json:"id"`
	LocalDeviceID     string    `json:"local_device_id"`
	RemoteDeviceID    string    `json:"remote_device_id"`
	RemoteName        string    `json:"remote_name"`
	RemoteFingerprint string    `json:"remote_fingerprint"` // hex 64 快照（来自 Registry）
	LastConnectedAt   time.Time `json:"last_connected_at"`
	LastOverlayIP     string    `json:"last_overlay_ip"`
	LastPath          string    `json:"last_path"` // directlink | n2n
	ConnectionCount   int64     `json:"connection_count"`
	CreatedAt         time.Time `json:"created_at"`
}

// CredentialInfo 设备 Controller credential（仅 hash 入库；明文只在注册响应出现一次）。
type CredentialInfo struct {
	DeviceID       string
	CredentialHash string // hex sha256
	CreatedAt      time.Time
}

// ConnectionSession 6 位码连接会话。
type ConnectionSession struct {
	SessionID       string        `json:"session_id"`
	Code            string        `json:"code"` // 6 digits 000000-999999
	CreatorDeviceID string        `json:"creator_device_id"`
	NetworkID       string        `json:"network_id"`
	Status          SessionStatus `json:"status"`
	CreatedAt       time.Time     `json:"created_at"`
	ExpiresAt       time.Time     `json:"expires_at"`
	// OverlaySubnet 本会话独占的 overlay /24（如 "10.88.7.0/24"）。
	// 创建时由 Controller IPAM 从事先配置的地址池分配（规格六：禁止客户端
	// 硬编码 A=.2 / B=.3），active 会话间唯一，过期清理后回收复用。
	OverlaySubnet string `json:"overlay_subnet,omitempty"`
}

// SessionMember 会话成员（含加入时刻的公钥快照，公钥轮换不影响既有会话验证）。
type SessionMember struct {
	SessionID      string     `json:"session_id"`
	DeviceID       string     `json:"device_id"`
	Role           MemberRole `json:"role"`
	NoisePublicKey string     `json:"noise_public_key"` // hex 64 快照
	JoinedAt       time.Time  `json:"joined_at"`
	// OverlayIP 该成员在本会话 overlay 子网内的 IPv4（Controller IPAM 分配，
	// 会话内唯一；creator 创建即得，joiner 加入即得）。
	OverlayIP string `json:"overlay_ip,omitempty"`
}

// Candidate ICE 候选（与 directlink CandidateWire 对应：u32 ip + u16 port + kind）。
type Candidate struct {
	IP   string `json:"ip"`   // IPv4 点分十进制
	Port uint16 `json:"port"` // 1..65535
	Kind string `json:"kind"` // host | srflx
}

// SessionCandidates 某成员在某会话上传的候选集。
// Supernode M1-2: Supernode Registry member (priority + health).
type Supernode struct {
	ID       string    `json:"id"`
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	Priority int       `json:"priority"`
	Healthy  bool      `json:"healthy"`
	LastSeen time.Time `json:"last_seen"`
}

type SessionCandidates struct {
	SessionID  string      `json:"session_id"`
	DeviceID   string      `json:"device_id"`
	Candidates []Candidate `json:"candidates"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

// FriendInvite 好友邀请（与 6 位码完全独立、可长期存在的授权）。
type FriendInvite struct {
	InviteID        string       `json:"invite_id"`
	InviteTokenHash string       `json:"-"` // hex sha256，绝不外发
	CreatorDeviceID string       `json:"creator_device_id"`
	NetworkID       string       `json:"network_id"`
	ExpiresAt       *time.Time   `json:"expires_at,omitempty"` // nil = 永久
	MaxUses         int64        `json:"max_uses"`             // 0 = 不限次
	UsedCount       int64        `json:"used_count"`
	Status          InviteStatus `json:"status"`
	CreatedAt       time.Time    `json:"created_at"`
}

// InviteRedemption 邀请兑换记录（一次兑换 = 一条 PENDING 好友关系）。
type InviteRedemption struct {
	InviteID       string    `json:"invite_id"`
	JoinerDeviceID string    `json:"joiner_device_id"`
	RedeemedAt     time.Time `json:"redeemed_at"`
	FriendshipID   string    `json:"friendship_id"`
}

// 常量：会话默认有效期 10 分钟（用户指定）；邀请档位；在线判定窗口。
const (
	SessionTTLDefault   = 10 * time.Minute
	InviteTTL24h        = 24 * time.Hour
	InviteTTL7d         = 7 * 24 * time.Hour
	MaxCandidatesPerPut = 16
	PublicKeyHexLen     = 64
	CandidateKindHost   = "host"
	CandidateKindSrflx  = "srflx"
	// PresenceOnlineWindow 设备在线判定窗口（last_seen_at 新鲜度阈值）。
	PresenceOnlineWindow = 90 * time.Second
)

// Overlay 地址池默认值（规格六：具体地址池通过配置定义，勿硬编码到客户端）。
// 池按 /24 切分给每个连接会话（M0 快速连接 = 一对一，/24 足够且留扩展余地）。
const (
	OverlayPoolDefault  = "10.88.0.0/16"
	OverlaySubnetPrefix = 24 // 每会话 /24
)
