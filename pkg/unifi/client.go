package unifi

import (
	"context"
	"fmt"
	"github.com/unpoller/unifi"
	"net"
	"regexp"
	"strings"
)

type IClient interface {
	GetSites() ([]*unifi.Site, error)
	GetClients([]*unifi.Site) ([]*unifi.Client, error)
}

type Client struct {
	Client IClient
}

func NewClient(user, pass, url string) (*Client, error) {
	c := &unifi.Config{
		User: user,
		Pass: pass,
		URL:  url,
	}

	client, err := unifi.NewUnifi(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create Unifi Client: %w", err)
	}

	return &Client{
		Client: client,
	}, nil
}

type Host struct {
	Name string
	Addr *net.IP
}

var dnsNameRegex = regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-_]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)

func (c *Client) GetSites(ctx context.Context) ([]*unifi.Site, error) {
	sites, err := c.Client.GetSites()
	if err != nil {
		return nil, fmt.Errorf("failed to get Sites: %w", err)
	}
	return sites, nil
}

func (c *Client) GetHosts(ctx context.Context, sites []*unifi.Site) ([]*Host, error) {
	clients, err := c.Client.GetClients(sites)
	if err != nil {
		return nil, fmt.Errorf("failed to get Clients: %w", err)
	}

	hosts := make([]*Host, 0, len(clients))
	for _, client := range clients {
		sec := strings.Split(client.Hostname, ".")
		name := sec[0]
		if dnsNameRegex.MatchString(name) {
			ip := net.ParseIP(client.IP)
			hosts = append(
				hosts,
				&Host{
					Name: name,
					Addr: &ip,
				})
		}
	}
	return hosts, nil
}
