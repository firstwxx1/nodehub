package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
)

// rawCodec lets us speak the stats gRPC API with hand-encoded protobuf, so the agent
// does not need to import xray-core or sing-box. Name must be "proto" for the server to accept it.
type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("rawCodec: want *[]byte, got %T", v)
	}
	return *b, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawCodec: want *[]byte, got %T", v)
	}
	*b = append((*b)[:0], data...)
	return nil
}

func (rawCodec) Name() string { return "proto" }

// StatsClient queries the StatsService of Xray or sing-box.
type StatsClient struct {
	addr    string
	service string // "xray.app.stats.command.StatsService" or "experimental.v2rayapi.StatsService"
	conn    *grpc.ClientConn
}

func NewStatsClient(addr, service string) (*StatsClient, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})))
	if err != nil {
		return nil, err
	}
	return &StatsClient{addr: addr, service: service, conn: conn}, nil
}

func (c *StatsClient) Close() { c.conn.Close() }

// Query returns name->value for all counters matching pattern, optionally resetting them.
func (c *StatsClient) Query(pattern string, reset bool) (map[string]int64, error) {
	var req []byte
	req = protowire.AppendTag(req, 1, protowire.BytesType)
	req = protowire.AppendString(req, pattern)
	if reset {
		req = protowire.AppendTag(req, 2, protowire.VarintType)
		req = protowire.AppendVarint(req, 1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var resp []byte
	if err := c.conn.Invoke(ctx, "/"+c.service+"/QueryStats", &req, &resp); err != nil {
		return nil, err
	}
	out := map[string]int64{}
	err := walk(resp, func(num protowire.Number, typ protowire.Type, val []byte, _ uint64) error {
		if num != 1 || typ != protowire.BytesType {
			return nil
		}
		var name string
		var value int64
		err := walk(val, func(n protowire.Number, t protowire.Type, v []byte, u uint64) error {
			switch {
			case n == 1 && t == protowire.BytesType:
				name = string(v)
			case n == 2 && t == protowire.VarintType:
				value = int64(u)
			}
			return nil
		})
		if err != nil {
			return err
		}
		out[name] = value
		return nil
	})
	return out, err
}

// OnlineIPs returns ip -> last seen unix time for an Xray user (requires statsUserOnline policy).
func (c *StatsClient) OnlineIPs(email string) (map[string]int64, error) {
	var req []byte
	req = protowire.AppendTag(req, 1, protowire.BytesType)
	req = protowire.AppendString(req, "user>>>"+email+">>>online")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var resp []byte
	if err := c.conn.Invoke(ctx, "/"+c.service+"/GetStatsOnlineIpList", &req, &resp); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return map[string]int64{}, nil
		}
		return nil, err
	}
	out := map[string]int64{}
	err := walk(resp, func(num protowire.Number, typ protowire.Type, val []byte, _ uint64) error {
		if num != 2 || typ != protowire.BytesType { // map<string,int64> ips = 2
			return nil
		}
		var k string
		var v int64
		_ = walk(val, func(n protowire.Number, t protowire.Type, b []byte, u uint64) error {
			if n == 1 && t == protowire.BytesType {
				k = string(b)
			} else if n == 2 && t == protowire.VarintType {
				v = int64(u)
			}
			return nil
		})
		if k != "" {
			out[k] = v
		}
		return nil
	})
	return out, err
}

func walk(b []byte, fn func(protowire.Number, protowire.Type, []byte, uint64) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return protowire.ParseError(m)
			}
			if err := fn(num, typ, nil, v); err != nil {
				return err
			}
			b = b[m:]
		case protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return protowire.ParseError(m)
			}
			if err := fn(num, typ, v, 0); err != nil {
				return err
			}
			b = b[m:]
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return protowire.ParseError(m)
			}
			b = b[m:]
		}
	}
	return nil
}
