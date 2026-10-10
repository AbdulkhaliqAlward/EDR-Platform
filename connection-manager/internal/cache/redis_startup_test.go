package cache

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// Loopback RESP fixture exercises the actual go-redis connection/handshake,
// including the LOADING error from the deployed Redis startup log.
func loadingRedis(t *testing.T, recover bool) (string, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var connections atomic.Int32
	var mu sync.Mutex
	var conns []net.Conn
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(acceptDone)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			connectionNumber := connections.Add(1)
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if !strings.HasPrefix(line, "*") {
						return
					}
					n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
					if err != nil {
						return
					}
					args := make([]string, n)
					for i := range args {
						line, err = r.ReadString('\n')
						if err != nil {
							return
						}
						if !strings.HasPrefix(line, "$") {
							return
						}
						size, err := strconv.Atoi(strings.TrimSpace(line[1:]))
						if err != nil || size < 0 || size > 4096 {
							return
						}
						b := make([]byte, size+2)
						if _, err = io.ReadFull(r, b); err != nil {
							return
						}
						args[i] = string(b[:size])
					}
					if len(args) == 0 {
						return
					}
					switch strings.ToLower(args[0]) {
					case "hello":
						fmt.Fprint(c, "%0\r\n")
					case "ping":
						requests.Add(1)
						if recover && connectionNumber > 1 {
							fmt.Fprint(c, "+PONG\r\n")
						} else {
							fmt.Fprint(c, "-LOADING Redis is loading the dataset in memory\r\n")
						}
					default:
						fmt.Fprint(c, "+OK\r\n")
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-acceptDone
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l.Addr().String(), &requests
}

func TestWaitForRedisLoadingThenRecovery(t *testing.T) {
	addr, attempts := loadingRedis(t, true)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := WaitForRedis(ctx, &RedisConfig{Addr: addr}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if attempts.Load() < 2 {
		t.Fatal("startup did not retry LOADING")
	}
	if err := client.Client().Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForRedisDeadlineDoesNotReturnDegradedClient(t *testing.T) {
	addr, _ := loadingRedis(t, false)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	client, err := WaitForRedis(ctx, &RedisConfig{Addr: addr}, logger)
	if err == nil || client != nil {
		t.Fatalf("startup must fail closed: client=%v err=%v", client, err)
	}
}
