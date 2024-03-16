package tailscale

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/google/go-cmp/cmp"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/tailscale/tailscale-client-go/tailscale"
)

type options struct {
	aaaa            bool
	reload          time.Duration
	ttl             uint32
	token           string
	tailnet         string
	fall            fall.F
	enableFullName  bool
	caseSensitive   bool
	disableTopLevel bool
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

func (h *Tailscale) Debugf(msg string, args ...any) {
	clog.Debugf("wireguard: "+msg, args...)
}

func (h *Tailscale) updateHosts(ctx context.Context) error {
	devices, err := h.tailscaleClient.Devices(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Devices: %w", err)
	}
	newMap := make(map[string]*Host, len(devices))
	for _, device := range devices {
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
		name := device.Name
		if h.options.enableFullName {
			newMap[name] = host
		}
		if !h.options.disableTopLevel {
			t := strings.Split(name, ".")[0]
			newMap[t] = host
		}
	}

	if clog.D.Value() {
		h.Debugf("hosts updated. diff: %s", cmp.Diff(h.hostMap, newMap))
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
			h.Debugf("no A record found. qname: %s", qname)
			break
		}
		answers = a(qname, h.options.ttl, []net.IP{*v.IP4})
	case dns.TypeAAAA:
		// handle AAAA queries only if options.aaaa is true
		if !h.options.aaaa {
			h.Debugf("queried for AAAA record but disabled. qname: %s", qname)
			break
		}
		h.mu.RLock()
		v, ok := h.hostMap[qname]
		h.mu.RUnlock()
		if !ok {
			h.Debugf("no AAAA record found for %s.", qname)
			break
		}
		answers = aaaa(qname, h.options.ttl, []net.IP{*v.IP6})
	default:
		h.Debugf("ignored the query has unexpected type. query: %s, type: %d", qname, state.QType())
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
	}

	// if no answers, return failure unless fallthrough is enabled
	if len(answers) == 0 {
		if h.options.fall.Through(qname) {
			h.Debugf("no record found. qname: %s", qname)
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

	h.Debugf("found record. qname: %s, answer: %v", qname, answers)
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
