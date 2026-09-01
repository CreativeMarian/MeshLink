// 存储层辅助：随机码 / ID / 候选编解码 / credential 生成与哈希。

package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"meshlink/server/controller/internal/model"
)

// randomCode 均匀随机 6 位数字（000000-999999），crypto/rand 拒绝采样无取模偏差。
func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("rand code: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// codeGen 会话码生成器：生产默认随机；测试可注入确定性序列消除 flake。
var codeGen = randomCode

// newID 生成带前缀的 URL 安全随机 ID（crypto/rand 16 字节 hex）。
func newID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败属系统级故障（不应静默降级到弱随机）。
		panic(fmt.Sprintf("crypto/rand failure: %v", err))
	}
	return prefix + "_" + hex.EncodeToString(b)
}

// NewCredential 生成设备 Controller credential：32 字节 CSPRNG，hex 64 字符
// （高随机熵；仅注册响应下发一次，Controller 只保存 SHA-256 hash）。
func NewCredential() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failure: %v", err))
	}
	return "mlk_" + hex.EncodeToString(b)
}

// NewInviteToken 生成好友邀请 token（32 字节 CSPRNG hex；仅创建响应下发一次）。
func NewInviteToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failure: %v", err))
	}
	return "mli_" + hex.EncodeToString(b)
}

// HashToken 计算 token/credential 的 SHA-256 hex（小写）。
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// constantTimeEqualHex 常量时间比较两个 hex 字符串（等长才比较）。
func constantTimeEqualHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func encodeCandidates(cands []model.Candidate) (string, error) {
	if len(cands) > model.MaxCandidatesPerPut {
		return "", fmt.Errorf("candidates exceed limit %d", model.MaxCandidatesPerPut)
	}
	blob, err := json.Marshal(cands)
	if err != nil {
		return "", fmt.Errorf("encode candidates: %w", err)
	}
	return string(blob), nil
}

func decodeCandidates(blob string) ([]model.Candidate, error) {
	var cands []model.Candidate
	if err := json.Unmarshal([]byte(blob), &cands); err != nil {
		return nil, fmt.Errorf("decode candidates: %w", err)
	}
	if len(cands) > model.MaxCandidatesPerPut {
		return nil, fmt.Errorf("stored candidates exceed limit")
	}
	return cands, nil
}

// ValidPublicKeyHex 校验 Noise X25519 静态公钥（hex 64，解码后 32 字节）。
func ValidPublicKeyHex(s string) bool {
	if len(s) != model.PublicKeyHexLen {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ValidDeviceID 与 Rust 侧 validate_device_id 对齐：非空、≤64、ASCII 可见字符。
func ValidDeviceID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}
