// meshlink Controller（M0 Controller MVP）。
//
// 职责边界（用户规格十二）：Identity / Signaling / Session / Invite /
// Candidate / Policy metadata——禁止任何数据面转发（文件 / Overlay packet /
// 普通 UDP relay 均不实现；N2N / Cloudflare Relay 为后续独立模块）。
//
// TLS 策略（用户规格十四）：生产模式只允许 HTTPS/WSS——由 TLS 终结层
// （Cloudflare Tunnel 等）提供；本进程监听明文 HTTP，仅限 localhost DEV
// 模式（启动横幅强制声明）。暴露到公网必须置于 TLS 终结层之后。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"meshlink/server/controller/internal/api"
	"meshlink/server/controller/internal/events"
	"meshlink/server/controller/internal/model"
	"meshlink/server/controller/internal/ratelimit"
	"meshlink/server/controller/internal/store"
)

const version = "0.2.0-m0-controller-mvp"

// 全局唯一默认 Controller 监听地址（用户规格二：单一 Default）。
// 必须与 mesh-ipc 的 DEFAULT_CONTROLLER_URL（http://127.0.0.1:18080）保持一致——
// 任何改动需同步两端，并由 TestDefaultAddrIsCanonical 拦截漂移。
const (
	DefaultControllerHost = "127.0.0.1"
	DefaultControllerPort = "18080"
	DefaultAddr           = DefaultControllerHost + ":" + DefaultControllerPort
)

func main() {
	var (
		listen     = flag.String("addr", envOr("CONTROLLER_LISTEN", DefaultAddr), "监听地址（DEV 默认 localhost:"+DefaultControllerPort+"）")
		dbPath     = flag.String("db", envOr("CONTROLLER_DB", "controller.db"), "SQLite 数据库路径")
		trustProxy = flag.Bool("trust-proxy", os.Getenv("CONTROLLER_TRUST_PROXY") == "1",
			"信任 X-Forwarded-For（仅在 TLS 终结代理后开启）")
		tlsCert     = flag.String("tls-cert", envOr("CONTROLLER_TLS_CERT", ""), "TLS 证书 PEM（提供后启用 HTTPS 原生监听）")
		tlsKey      = flag.String("tls-key", envOr("CONTROLLER_TLS_KEY", ""), "TLS 私钥 PEM（与 tls-cert 成对）")
		overlayPool = flag.String("overlay-pool", envOr("CONTROLLER_OVERLAY_POOL", "10.88.0.0/16"),
			"Overlay IPAM 地址池 CIDR（每个连接会话从中切一个 /24）")
		allowLanPlaintext = flag.Bool("allow-lan-plaintext", os.Getenv("CONTROLLER_ALLOW_LAN_PLAINTEXT") == "1",
			"允许明文 HTTP 监听私网地址（仅 RFC1918 局域网；公网明文永远禁止）")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	tlsEnabled := *tlsCert != "" && *tlsKey != ""
	if (*tlsCert != "") != (*tlsKey != "") {
		logger.Error("tls-cert and tls-key must be provided together")
		os.Exit(2)
	}

	// 监听策略：
	//   - 明文 HTTP：仅 localhost DEV 模式（启动横幅强制声明）；
	//   - 原生 TLS（--tls-cert/--tls-key）：HTTPS 监听，任意地址；
	//   - 生产公网也可以置于 TLS 终结层（Cloudflare Tunnel 等）之后，
	//     此时本进程仍明文但只绑定内网地址（trust-proxy 开启）。
	//   - 局域网双机联机：私网地址 + -allow-lan-plaintext 显式放行
	//     （仅 RFC1918；公网明文即使加开关也拒绝）。
	if !tlsEnabled {
		loop := isLoopback(*listen)
		lan := isPrivate(*listen)
		ok := loop || (lan && *allowLanPlaintext)
		if ok {
			banner := "DEV MODE ONLY (plaintext HTTP): production must terminate TLS (HTTPS/WSS) in front of this listener"
			fmt.Fprintln(os.Stderr, "=======================================================================")
			fmt.Fprintln(os.Stderr, banner)
			fmt.Fprintln(os.Stderr, "listen="+*listen, "db="+*dbPath, "overlay-pool="+*overlayPool)
			if lan && !loop {
				fmt.Fprintln(os.Stderr, "LAN PLAINTEXT ENABLED (RFC1918 only): use only on a trusted local network")
			}
			fmt.Fprintln(os.Stderr, "=======================================================================")
			logger.Warn(banner, "listen", *listen)
		} else {
			// 非回环/非私网明文：拒绝启动（公网明文永远禁止）。
			logger.Error("refusing plaintext listener on non-loopback/non-private address; use --tls-cert/--tls-key or put a TLS terminator in front",
				"listen", *listen)
			os.Exit(2)
		}
	}

	st, err := store.OpenWithOverlayPool(*dbPath, *overlayPool)
	if err != nil {
		logger.Error("open store failed", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	// M1-2：Supernode Registry 种子（env MESHLINK_SUPERNODES = JSON 数组）。
	// 生产由 Supernode 进程自注册 + 心跳；本地/测试可从环境预置。
	if sns, ok := seedSupernodes(); ok {
		for _, sn := range sns {
			if err := st.UpsertSupernode(context.Background(), sn); err != nil {
				logger.Warn("seed supernode failed", "id", sn.ID, "err", err)
				continue
			}
			logger.Info("seeded supernode", "id", sn.ID, "host", sn.Host, "port", sn.Port)
		}
	}

	lim := ratelimit.NewTracker(ratelimit.Config{Window: time.Minute, MaxFails: 10})
	bus := events.NewBus()
	srv := api.NewServer(st, lim, bus, *trustProxy, logger)

	// 过期清理：每 30 秒删除过期会话（级联 members/candidates——
	// 同时回收该会话占用的 overlay 子网供后续会话复用）。
	cleanupCtx, cancelCleanup := context.WithCancel(context.Background())
	defer cancelCleanup()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupCtx.Done():
				return
			case <-ticker.C:
				if n, err := st.CleanupExpired(cleanupCtx); err != nil {
					logger.Warn("cleanup failed", "err", err)
				} else if n > 0 {
					logger.Info("expired rows cleaned", "count", n)
				}
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	logger.Info("controller started", "addr", *listen, "version", version, "db", *dbPath,
		"tls", tlsEnabled, "overlay-pool", *overlayPool)
	if tlsEnabled {
		// 原生 HTTPS：客户端以 https:// 直连（Cloudflare Tunnel 场景下由 Tunnel
		// 终结 TLS，本进程保持明文内网监听——两种部署客户端均只见 https://）。
		if err := httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
			logger.Error("server exited", "err", err)
			os.Exit(1)
		}
		return
	}
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server exited", "err", err)
		os.Exit(1)
	}
}

// seedSupernodes 读取 MESHLINK_SUPERNODES 环境变量（JSON 数组）预置 Registry。
func seedSupernodes() ([]model.Supernode, bool) {
	raw := os.Getenv("MESHLINK_SUPERNODES")
	if strings.TrimSpace(raw) == "" {
		return nil, false
	}
	var list []struct {
		ID       string `json:"id"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Priority int    `json:"priority"`
	}
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		slog.Warn("invalid MESHLINK_SUPERNODES", "err", err)
		return nil, false
	}
	out := []model.Supernode{}
	for _, e := range list {
		if e.ID == "" || e.Host == "" || e.Port <= 0 {
			continue
		}
		if e.Priority <= 0 {
			e.Priority = 100
		}
		out = append(out, model.Supernode{
			ID: e.ID, Host: e.Host, Port: e.Port, Priority: e.Priority,
			Healthy: true, LastSeen: time.Now().UTC(),
		})
	}
	return out, len(out) > 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// isLoopback 判定监听地址是否回环（localhost / 127.x / ::1）。
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isPrivate 判定监听地址是否 RFC1918 私网（局域网联机用）。
// 公网地址即使传入也返回 false——`-allow-lan-plaintext` 只放行私网。
func isPrivate(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}
