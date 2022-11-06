package chserver

import (
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	chshare "github.com/myzhang1029/penguin/share"
	"github.com/myzhang1029/penguin/share/cnet"
	"github.com/myzhang1029/penguin/share/settings"
	"github.com/myzhang1029/penguin/share/tunnel"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

// handleClientHandler is the main http websocket handler for the penguin server
func (s *Server) handleClientHandler(w http.ResponseWriter, r *http.Request) {
	//websockets upgrade AND has penguin prefix
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	protocol := r.Header.Get("Sec-WebSocket-Protocol")
	wsPsk := r.Header.Get("X-Penguin-Psk")
	if upgrade == "websocket" && strings.HasPrefix(protocol, "penguin-") {
		if s.config.Psk == "" || wsPsk == s.config.Psk {
			if protocol == chshare.ProtocolVersion {
				s.handleWebsocket(w, r)
				return
			}
			//print into server logs and silently fall-through
			s.Infof("ignoring client connection using protocol '%s', expected '%s'",
				protocol, chshare.ProtocolVersion)
		} else {
			s.Infof("ignoring client connection with incorrect or missing PSK '%s'",
				wsPsk)
		}
	}
	//proxy target was provided
	if s.reverseProxy != nil {
		s.reverseProxy.ServeHTTP(w, r)
		return
	}
	if !s.config.Obfs {
		//no proxy defined, provide access to health/version checks
		switch r.URL.Path {
		case "/health":
			w.Write([]byte("OK\n"))
			return
		case "/version":
			w.Write([]byte(chshare.BuildVersion))
			return
		}
	}
	//missing :O
	w.WriteHeader(404)
	w.Write([]byte(s.config.Resp404))
}

// handleWebsocket is responsible for handling the websocket connection
func (s *Server) handleWebsocket(w http.ResponseWriter, req *http.Request) {
	id := atomic.AddInt32(&s.sessCount, 1)
	l := s.Fork("session#%d", id)
	wsConn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		l.Debugf("failed to upgrade (%s)", err)
		return
	}
	conn := cnet.NewWebSocketConn(wsConn)
	// perform SSH handshake on net.Conn
	l.Debugf("handshaking with %s...", req.RemoteAddr)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.Debugf("failed to handshake (%s)", err)
		return
	}
	// pull the users from the session map
	var user *settings.User
	if s.users.Len() > 0 {
		sid := string(sshConn.SessionID())
		u, ok := s.sessions.Get(sid)
		if !ok {
			panic("bug in ssh auth handler")
		}
		user = u
		s.sessions.Del(sid)
	}
	// penguin server handshake (reverse of client handshake)
	// verify configuration
	l.Debugf("verifying configuration")
	// wait for request, with timeout
	var r *ssh.Request
	select {
	case r = <-reqs:
	case <-time.After(settings.EnvDuration("CONFIG_TIMEOUT", 10*time.Second)):
		l.Debugf("timeout waiting for configuration")
		sshConn.Close()
		return
	}
	failed := func(err error) {
		l.Debugf("failed: %s", err)
		r.Reply(false, []byte(err.Error()))
	}
	if r.Type != "config" {
		failed(s.Errorf("expecting config request"))
		return
	}
	c, err := settings.DecodeConfig(r.Payload)
	if err != nil {
		failed(s.Errorf("invalid config"))
		return
	}
	//print if client and server versions dont match
	if c.Version != chshare.BuildVersion {
		v := c.Version
		if v == "" {
			v = "<unknown>"
		}
		l.Infof("client version (%s) differs from server version (%s)",
			v, chshare.BuildVersion)
	}
	//validate remotes
	for _, r := range c.Remotes {
		//if user is provided, ensure they have
		//access to the desired remotes
		if user != nil {
			addr := r.UserAddr()
			if !user.HasAccess(addr) {
				failed(s.Errorf("access to '%s' denied", addr))
				return
			}
		}
		//confirm reverse tunnels are allowed
		if r.Reverse && !s.config.Reverse {
			l.Debugf("denied reverse port forwarding request, please enable --reverse")
			failed(s.Errorf("reverse port forwarding not enabled on server"))
			return
		}
		//confirm reverse tunnel is available
		if r.Reverse && !r.CanListen() {
			failed(s.Errorf("server cannot listen on %s", r.String()))
			return
		}
	}
	//successfully validated config!
	r.Reply(true, nil)
	//tunnel per ssh connection
	tunnel := tunnel.New(tunnel.Config{
		Logger:    l,
		Inbound:   s.config.Reverse,
		Outbound:  true, //server always accepts outbound
		Socks:     s.config.Socks5,
		KeepAlive: s.config.KeepAlive,
	})
	//bind
	eg, ctx := errgroup.WithContext(req.Context())
	eg.Go(func() error {
		//connected, handover ssh connection for tunnel to use, and block
		return tunnel.BindSSH(ctx, sshConn, reqs, chans)
	})
	eg.Go(func() error {
		//connected, setup reversed-remotes?
		serverInbound := c.Remotes.Reversed(true)
		if len(serverInbound) == 0 {
			return nil
		}
		//block
		return tunnel.BindRemotes(ctx, serverInbound)
	})
	err = eg.Wait()
	if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
		l.Debugf("closed connection (%s)", err)
	} else {
		l.Debugf("closed connection")
	}
}
