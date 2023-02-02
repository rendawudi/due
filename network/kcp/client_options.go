package kcp

import (
	"crypto/sha1"
	"github.com/dobyte/due/config"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
	"time"
)

const (
	defaultClientDialAddr          = "127.0.0.1:3553"
	defaultClientMaxMsgLen         = 1024
	defaultClientHeartbeat         = false
	defaultClientHeartbeatInterval = 10
)

const (
	defaultClientDialAddrKey          = "config.network.kcp.client.addr"
	defaultClientMaxMsgLenKey         = "config.network.kcp.client.maxMsgLen"
	defaultClientHeartbeatKey         = "config.network.kcp.client.heartbeat"
	defaultClientHeartbeatIntervalKey = "config.network.kcp.client.heartbeatInterval"
)

type ClientOption func(o *clientOptions)

type clientOptions struct {
	addr              string        // 地址
	maxMsgLen         int           // 最大消息长度
	enableHeartbeat   bool          // 是否启用心跳，默认不启用
	heartbeatInterval time.Duration // 心跳间隔时间，默认10s
	blockCrypt        kcp.BlockCrypt
	dataShards        int
	parityShards      int
	ackNoDelay        bool
	noDelay           int
	kcpInterval       int
	kcpResend         int
	kcpNc             int
}

func defaultClientOptions() *clientOptions {
	return &clientOptions{
		addr:              config.Get(defaultClientDialAddrKey, defaultClientDialAddr).String(),
		maxMsgLen:         config.Get(defaultClientMaxMsgLenKey, defaultClientMaxMsgLen).Int(),
		enableHeartbeat:   config.Get(defaultClientHeartbeatKey, defaultClientHeartbeat).Bool(),
		heartbeatInterval: config.Get(defaultClientHeartbeatIntervalKey, defaultClientHeartbeatInterval).Duration() * time.Second,
		blockCrypt:        nil,
		dataShards:        0,
		parityShards:      0,
		ackNoDelay:        false,
		noDelay:           1,
		kcpInterval:       10,
		kcpResend:         2,
		kcpNc:             1,
	}
}

// WithClientDialAddr 设置拨号地址
func WithClientDialAddr(addr string) ClientOption {
	return func(o *clientOptions) { o.addr = addr }
}

// WithClientMaxMsgLen 设置消息最大长度
func WithClientMaxMsgLen(maxMsgLen int) ClientOption {
	return func(o *clientOptions) { o.maxMsgLen = maxMsgLen }
}

// WithClientEnableHeartbeat 设置是否启用心跳间隔时间
func WithClientEnableHeartbeat(enable bool) ClientOption {
	return func(o *clientOptions) { o.enableHeartbeat = enable }
}

// WithClientHeartbeatInterval 设置心跳间隔时间
func WithClientHeartbeatInterval(heartbeatInterval time.Duration) ClientOption {
	return func(o *clientOptions) { o.heartbeatInterval = heartbeatInterval }
}

// WithClientSM4BlockCrypt 设置Kcp加解密规则
func WithClientSM4BlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewSM4BlockCrypt(pass[:16]) }
}

// WithClientTEABlockCrypt 设置Kcp加解密规则
func WithClientTEABlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewTEABlockCrypt(pass[:16]) }
}

// WithClientSimpleXORBlockCrypt 设置Kcp加解密规则
func WithClientSimpleXORBlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewSimpleXORBlockCrypt(pass) }
}

// WithClientNoneBlockCrypt 设置Kcp加解密规则
func WithClientNoneBlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewNoneBlockCrypt(pass) }
}

// WithClientAES128BlockCrypt 设置Kcp加解密规则
func WithClientAES128BlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewAESBlockCrypt(pass[:16]) }
}

// WithClient192BlockCrypt 设置Kcp加解密规则
func WithClient192BlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewAESBlockCrypt(pass[:24]) }
}

// WithClientBlowfishBlockCrypt 设置Kcp加解密规则
func WithClientBlowfishBlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewBlowfishBlockCrypt(pass) }
}

// WithClientTwofishBlockCrypt 设置Kcp加解密规则
func WithClientTwofishBlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewTwofishBlockCrypt(pass) }
}

// WithClientCast5BlockCrypt 设置Kcp加解密规则
func WithClientCast5BlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewCast5BlockCrypt(pass[:16]) }
}

// WithClientTripleDESBlockCrypt 设置Kcp加解密规则
func WithClientTripleDESBlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewTripleDESBlockCrypt(pass[:24]) }
}

// WithClientXTEABlockCrypt 设置Kcp加解密规则
func WithClientXTEABlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewXTEABlockCrypt(pass[:16]) }
}

// WithClientSalsa20BlockCrypt 设置Kcp加解密规则
func WithClientSalsa20BlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewSalsa20BlockCrypt(pass) }
}

// WithClientAESBlockCrypt 设置Kcp加解密规则
func WithClientAESBlockCrypt(key, salt string) ClientOption {
	pass := pbkdf2.Key([]byte(key), []byte(salt), 4096, 32, sha1.New)
	return func(o *clientOptions) { o.blockCrypt, _ = kcp.NewAESBlockCrypt(pass) }
}

// WithClientDataShardsAndParityShards 设置Kcp加解密规则
func WithClientDataShardsAndParityShards(dataShards, parityShards int) ClientOption {
	return func(o *clientOptions) {
		o.dataShards = dataShards
		o.parityShards = parityShards
	}
}

// WithClientAckAndSend 设置Kcp加解密规则
func WithClientAckAndSend(ackNoDelay bool, sendNoDelay, interval, resend, nc int) ClientOption {
	return func(o *clientOptions) {
		o.ackNoDelay = ackNoDelay
		o.noDelay = sendNoDelay
		o.kcpInterval = interval
		o.kcpResend = resend
		o.kcpNc = nc
	}
}
