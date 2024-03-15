package tailscale

import (
	"context"
	"fmt"
	"github.com/tailscale/tailscale-client-go/tailscale"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("tailscale")

func init() { plugin.Register("tailscale", setup) }

func periodicHostsUpdate(h *Tailscale) chan bool {
	parseChan := make(chan bool)

	if h.options.reload == 0 {
		return parseChan
	}
	ctx := context.Background()

	go func() {
		ticker := time.NewTicker(h.options.reload)
		defer ticker.Stop()
		for {
			select {
			case <-parseChan:
				return
			case <-ticker.C:
				err := h.updateHosts(ctx)
				if err != nil {
					log.Errorf("Failed to update hosts: %s", err)
					return
				}
			}
		}
	}()
	return parseChan
}

func setup(c *caddy.Controller) error {
	h, err := hostsParse(c)
	if err != nil {
		return plugin.Error("hosts", err)
	}

	parseChan := periodicHostsUpdate(h)

	c.OnStartup(func() error {
		err := h.updateHosts(context.Background())
		if err != nil {
			return fmt.Errorf("failed to get hosts: %w", err)
		}
		return nil
	})

	c.OnShutdown(func() error {
		close(parseChan)
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})

	return nil
}

func hostsParse(c *caddy.Controller) (*Tailscale, error) {
	h := &Tailscale{}
	i := 0
	for c.Next() {
		if i > 0 {
			return h, plugin.ErrOnce
		}
		i++

		args := c.RemainingArgs()

		if len(args) != 2 {
			return h, c.ArgErr()
		}
		h.options.tailnet = args[0]
		h.options.token = args[1]
		h.options.ttl = 60
		h.options.reload = 60 * time.Second
		h.options.enableFullName = true

		var err error
		h.tailscaleClient, err = tailscale.NewClient(h.options.token, h.options.tailnet)
		if err != nil {
			return h, fmt.Errorf("failed to create Tailscale client: %w", err)
		}

		for c.NextBlock() {
			switch c.Val() {
			case "fallthrough":
				h.options.fall.SetZonesFromArgs(c.RemainingArgs())
			case "ttl":
				remaining := c.RemainingArgs()
				if len(remaining) < 1 {
					return h, c.Errf("ttl needs a time in second")
				}
				ttl, err := strconv.Atoi(remaining[0])
				if err != nil {
					return h, c.Errf("ttl needs a number of second")
				}
				if ttl <= 0 || ttl > 65535 {
					return h, c.Errf("ttl must be between 0 and 65535")
				}
				h.options.ttl = uint32(ttl)
			case "reload":
				remaining := c.RemainingArgs()
				reload := 60 * time.Second
				if len(remaining) == 1 {
					var err error
					reload, err = time.ParseDuration(remaining[0])
					if err != nil {
						return h, c.Errf("reload needs a duration string")
					}
				} else if len(remaining) > 1 {
					return h, c.Errf("too many arguments for reload")
				}
				h.options.reload = reload
			case "aaaa":
				h.options.aaaa = true
			case "casesensitive":
				h.options.caseSensitive = true
			case "fullname":
				h.options.enableFullName = true
			default:
				return h, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}
	return h, nil
}
