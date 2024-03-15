package test

import (
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"net"
)

// ResponseWriter is useful for writing tests. It uses some fixed values for the client. The
// remote will always be 10.240.0.1 and port 40212. The local address is always 127.0.0.1 and
// port 53.
type ResponseWriter struct {
	test.ResponseWriter
	Msg *dns.Msg
}

// LocalAddr returns the local address
func (t *ResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53, Zone: ""}
}

// RemoteAddr returns the remote address, defaults to 10.240.0.1:40212 (UDP, TCP is t.TCP is true).
func (t *ResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 4000, Zone: ""}
}

// WriteMsg implements dns.ResponseWriter interface.
func (t *ResponseWriter) WriteMsg(m *dns.Msg) error {
	t.Msg = m
	return nil
}
