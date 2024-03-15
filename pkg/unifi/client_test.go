package unifi

import (
	"context"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/unpoller/unifi"
	"github.com/xruins/unifi-coredns/pkg/test"
	"net"
	"testing"
)

var sites = []*unifi.Site{
	{
		ID:         "abcdef0123456789abcdef01",
		Name:       "default",
		SiteName:   "Default (default)",
		SourceName: "https://unifi",
	},
}

func TestClient_GetSites(t *testing.T) {
	ctx := context.Background()
	c := &test.MockClient{}

	client := &Client{Client: c}

	got, err := client.GetSites(ctx)
	if err != nil {
		t.Fatalf("failed to get Sites: %s", err)
	}

	want := sites
	diff := cmp.Diff(got, want, cmpopts.IgnoreUnexported(unifi.Site{}))
	if diff != "" {
		t.Errorf("GetSites() mismatch (-want, +got): %s", diff)
	}
}

func TestClient_GetHosts(t *testing.T) {
	ctx := context.Background()
	c := &test.MockClient{}
	client := &Client{Client: c}
	got, err := client.GetHosts(ctx, sites)
	if err != nil {
		t.Fatalf("failed to get Sites: %s", err)
	}

	ip := net.IPv4(192, 168, 1, 1)
	want := []*Host{
		{
			Name: "parsable",
			Addr: &ip,
		},
	}
	diff := cmp.Diff(got, want)
	if diff != "" {
		t.Errorf("GetSites() mismatch (-want, +got): %s", diff)
	}
}
