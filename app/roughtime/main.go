// roughtime: ask several Roughtime servers for signed time, using Cloudflare's
// reference implementation to build requests and verify replies. Prints one
// JSON line per server: {"name","midpoint_ms","radius_ms"} or {"name","error"}.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cloudflare/roughtime/protocol"
)

type server struct{ name, address, key string }

// From github.com/cloudflare/roughtime ecosystem.json.
var servers = []server{
	{"Cloudflare-Roughtime-2", "roughtime.cloudflare.com:2003", "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="},
	{"int08h-Roughtime", "roughtime.int08h.com:2002", "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE="},
	{"time.txryan.com", "time.txryan.com:2002", "iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA="},
}

// Servers differ in which drafts they answer, so try the newest first, then the original.
var preferences = [][]protocol.Version{{protocol.VersionDraft11, protocol.VersionDraft08}, {protocol.VersionGoogle}}

func query(s server, versions []protocol.Version) (time.Time, time.Duration, error) {
	key, err := base64.StdEncoding.DecodeString(s.key)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return time.Time{}, 0, fmt.Errorf("bad public key")
	}
	nonce, _, request, err := protocol.CreateRequest(versions, rand.Reader, nil, key)
	if err != nil {
		return time.Time{}, 0, err
	}
	conn, err := net.DialTimeout("udp", s.address, 3*time.Second)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(request); err != nil {
		return time.Time{}, 0, err
	}
	reply := make([]byte, 4096)
	n, err := conn.Read(reply)
	if err != nil {
		return time.Time{}, 0, err
	}
	return protocol.VerifyReply(versions, reply[:n], key, nonce)
}

func main() {
	out := json.NewEncoder(os.Stdout)
	for _, s := range servers {
		var err error
		for _, versions := range preferences {
			var midpoint time.Time
			var radius time.Duration
			if midpoint, radius, err = query(s, versions); err == nil {
				out.Encode(map[string]any{"name": s.name, "midpoint_ms": midpoint.UnixMilli(), "radius_ms": radius.Milliseconds()})
				break
			}
		}
		if err != nil {
			out.Encode(map[string]any{"name": s.name, "error": err.Error()})
		}
	}
}
