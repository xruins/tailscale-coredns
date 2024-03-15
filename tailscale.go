package tailscale

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/tailscale/tailscale-client-go/tailscale"
)

type options struct {
	aaaa           bool
	reload         time.Duration
	ttl            uint32
	token          string
	tailnet        string
	fall           fall.F
	enableFullName bool
	caseSensitive  bool
}

// Tailscale is the plugin handler to register Tailscale hosts to DNS
type Tailscale struct {
	Next    plugin.Handler
	options options

	mu              sync.RWMutex
	hostMap         map[string]*Host
	tailscaleClient *tailscale.Client
}

type Host struct {
	IP4 *net.IP
	IP6 *net.IP
}

func (h *Tailscale) updateHosts(ctx context.Context) error {
	devices, err := h.tailscaleClient.Devices(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Devices: %w", err)
	}
	newMap := make(map[string]*Host, len(devices))
	for _, device := range devices {
		name := strings.TrimPrefix(device.Name, h.options.tailnet)
		host := &Host{}
		for _, addr := range device.Addresses {
			ip := net.ParseIP(addr)
			if v4 := ip.To4(); v4 != nil {
				host.IP4 = &v4
				continue
			}
			if v6 := ip.To16(); v6 != nil {
				host.IP6 = &v6
				continue
			}
			return fmt.Errorf(
				"malformed IP address on the device. device: %s, address: %s",
				device.Name,
				addr,
			)
		}
		newMap[name] = host
	}

	// lock mutex before update hostMap and metrics
	h.mu.Lock()
	h.hostMap = newMap

	// update metrics for Prometheus
	tailscaleHostsEntries.WithLabelValues().Set(float64(len(h.hostMap)))
	tailscaleHostsReloadTime.Set(float64(time.Now().UnixNano() / 1e9))
	h.mu.Unlock()

	return nil
}

// ServeDNS implements the plugin.Handle interface.
func (h *Tailscale) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()
	if !h.options.caseSensitive {
		qname = strings.ToLower(qname)
	}

	var answers []dns.RR

	switch state.QType() {
	case dns.TypeA:
		// handle A queries
		h.mu.RLock()
		v, ok := h.hostMap[qname]
		h.mu.RUnlock()
		if !ok {
			return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
		}
		answers = a(qname, h.options.ttl, []net.IP{*v.IP4})
	case dns.TypeAAAA:
		// handle AAAA queries only if options.aaaa is true
		if !h.options.aaaa {
			return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
		}
		h.mu.RLock()
		v, ok := h.hostMap[qname]
		h.mu.RUnlock()
		if !ok {
			return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
		}
		answers = aaaa(qname, h.options.ttl, []net.IP{*v.IP6})
	default:
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
	}

	// if no answers, return failure unless fallthrough is enabled
	if len(answers) == 0 {
		if h.options.fall.Through(qname) {
			return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
		}
		return dns.RcodeServerFailure, nil
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = answers

	err := w.WriteMsg(m)
	if err != nil {
		return 0, fmt.Errorf("failed to write response message: %w", err)
	}
	return dns.RcodeSuccess, nil
}

// Name implements the plugin.Handle interface.
func (h *Tailscale) Name() string { return "tailscale" }

// a takes a slice of net.IPs and returns a slice of A RRs.
func a(zone string, ttl uint32, ips []net.IP) []dns.RR {
	answers := make([]dns.RR, len(ips))
	for i, ip := range ips {
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
		r.A = ip
		answers[i] = r
	}
	return answers
}

// aaaa takes a slice of net.IPs and returns a slice of AAAA RRs.
func aaaa(zone string, ttl uint32, ips []net.IP) []dns.RR {
	answers := make([]dns.RR, len(ips))
	for i, ip := range ips {
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
		r.AAAA = ip
		answers[i] = r
	}
	return answers
}
