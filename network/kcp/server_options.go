package kcp

import (
	"crypto/sha1"
	"github.com/dobyte/due/config"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
	"time"
)

const (
	defaultServerAddr                   = ":3553"
	defaultServerMaxMsgLen              = 1024
	defaultServerMaxConnNum             = 5000
	defaultServerHeartbeatCheck         = false
	defaultServerHeartbeatCheckInterval = 10
)

const (
	defaultServerAddrKey                   = "config.network.kcp.server.addr"
	defaultServerMaxMsgLenKey              = "config.network.kcp.server.maxMsgLen"
	defaultServerMaxConnNumKey             = "config.network.kcp.server.maxConnNum"
	defaultServerHeartbeatCheckKey         = "config.network.kcp.server.heartbeatCheck"
	defaultServerHeartbeatCheckIntervalKey = "config.network.kcp.server.heartbeatCheckInterval"
)

type ServerOption func(o *serverOptions)

type serverOptions struct {
	addr                   string        // 监听地址，默认0.0.0.0:3553
	maxMsgLen              int           // 最大消息长度，默认1K
	maxConnNum             int           // 最大连接数，默认5000
	enableHeartbeatCheck   bool          // 是否启用心跳检测，默认不启用
	heartbeatCheckInterval time.Duration // 心跳检测间隔时间，默认10s
	blockCrypt             kcp.BlockCrypt
	dataShards             int
	parityShards           int
	ackNoDelay             bool
	noDelay                int
	kcpInterval            int
	kcpResend              int
	kcpNc                  int
}

func defaultServerOptions() *serverOptions {
	return &serverOptions{
		addr:                   config.Get(defaultServerAddrKey, defaultServerAddr).String(),
		maxMsgLen:              config.Get(defaultServerMaxMsgLenKey, defaultServerMaxMsgLen).Int(),
		maxConnNum:             config.Get(defaultServerMaxConnNumKey, defaultServerMaxConnNum).Int(),
		enableHeartbeatCheck:   config.Get(defaultServerHeartbeatCheckKey, defaultServerHeartbeatCheck).Bool(),
		heartbeatCheckInterval: config.Get(defaultServerHeartbeatCheckIntervalKey, defaultServerHeartbeatCheckInterval).Duration() * time.Second,
		blockCrypt:             nil,
		dataShards:             0,
		parityShards:           0,
		ackNoDelay:             false,
		noDelay:                1,
		kcpInterval:            10,
		kcpResend:              2,
		kcpNc:                  1,
	}
}

// WithServerListenAddr 设置监听地址
func WithServerListenAddr(addr string) ServerOption {
	return func(o *serverOptions) { o.addr = addr }
}

// WithServerMaxMsgLen 设置消息最大长度
func WithServerMaxMsgLen(maxMsgLen int) ServerOption {
	return func(o *serverOptions) { o.maxMsgLen = maxMsgLen }
}

// WithServerMaxConnNum 设置连接的最大连接数
func WithServerMaxConnNum(maxConnNum int) ServerOption {
	return func(o *serverOptions) { o.maxConnNum = maxConnNum }
}

// WithServerEnableHeartbeatCheck 是否启用心跳检测
func WithServerEnableHeartbeatCheck(enable bool) ServerOption {
	return func(o *serverOptions) { o.enableHeartbeatCheck = enable }
}

// WithServerHeartbeatInterval 设置心跳检测间隔时间
func WithServerHeartbeatInterval(heartbeatInterval time.Duration) ServerOption {
	return func(o *serverOptions) { o.heartbeatCheckInterval = heartbeatInterval }
}

// WithSM4BlockCrypt 设置Kcp加解密规则
func WithSM4BlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewSM4BlockCrypt(pass[:16]) }
}

// WithTEABlockCrypt 设置Kcp加解密规则
func WithTEABlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewTEABlockCrypt(pass[:16]) }
}

// WithSimpleXORBlockCrypt 设置Kcp加解密规则
func WithSimpleXORBlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewSimpleXORBlockCrypt(pass) }
}

// WithNoneBlockCrypt 设置Kcp加解密规则
func WithNoneBlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewNoneBlockCrypt(pass) }
}

// WithAES128BlockCrypt 设置Kcp加解密规则
func WithAES128BlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewAESBlockCrypt(pass[:16]) }
}

// With192BlockCrypt 设置Kcp加解密规则
func With192BlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewAESBlockCrypt(pass[:24]) }
}

// WithBlowfishBlockCrypt 设置Kcp加解密规则
func WithBlowfishBlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewBlowfishBlockCrypt(pass) }
}

// WithTwofishBlockCrypt 设置Kcp加解密规则
func WithTwofishBlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewTwofishBlockCrypt(pass) }
}

// WithCast5BlockCrypt 设置Kcp加解密规则
func WithCast5BlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewCast5BlockCrypt(pass[:16]) }
}

// WithTripleDESBlockCrypt 设置Kcp加解密规则
func WithTripleDESBlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewTripleDESBlockCrypt(pass[:24]) }
}

// WithXTEABlockCrypt 设置Kcp加解密规则
func WithXTEABlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewXTEABlockCrypt(pass[:16]) }
}

// WithSalsa20BlockCrypt 设置Kcp加解密规则
func WithSalsa20BlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewSalsa20BlockCrypt(pass) }
}

// WithAESBlockCrypt 设置Kcp加解密规则
func WithAESBlockCrypt(key, salt string) ServerOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *serverOptions) { o.blockCrypt, _ = kcp.NewAESBlockCrypt(pass) }
}

// WithDataShardsAndParityShards 设置Kcp加解密规则
func WithDataShardsAndParityShards(dataShards, parityShards int) ServerOption {
	return func(o *serverOptions) {
		o.dataShards = dataShards
		o.parityShards = parityShards
	}
}

// WithAckAndSend 设置Kcp加解密规则
func WithAckAndSend(ackNoDelay bool, sendNoDelay, interval, resend, nc int) ServerOption {
	return func(o *serverOptions) {
		o.ackNoDelay = ackNoDelay
		o.noDelay = sendNoDelay
		o.kcpInterval = interval
		o.kcpResend = resend
		o.kcpNc = nc
	}
}
