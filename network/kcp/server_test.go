/**
 * @Author: rendawudi
 * @Date: 2022/5/11 11:31 上午
 * @Desc: TODO
 */

package kcp

import (
	"github.com/dobyte/due/network"
	"testing"
)

func TestServer(t *testing.T) {
	server := NewServer(
		WithServerEnableHeartbeatCheck(true))
	server.OnStart(func() {
		t.Logf("server is started")
	})
	server.OnConnect(func(conn network.Conn) {
		t.Logf("connection is opened, connection id: %d", conn.ID())
	})
	server.OnDisconnect(func(conn network.Conn) {
		t.Logf("connection is closed, connection id: %d", conn.ID())
	})
	server.OnReceive(func(conn network.Conn, msg []byte, msgType int) {
		t.Logf("receive msg from client, connection id: %d, msg: %s", conn.ID(), string(msg))

		if err := conn.Push([]byte("hello client~~")); err != nil {
			t.Error(err)
		}
	})

	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
}
