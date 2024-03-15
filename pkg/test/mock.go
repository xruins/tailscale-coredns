package test

import "github.com/unpoller/unifi"

type MockClient struct{}

func (*MockClient) GetSites() ([]*unifi.Site, error) {
	return []*unifi.Site{
		{
			ID:         "abcdef0123456789abcdef01",
			Name:       "default",
			SiteName:   "Default (default)",
			SourceName: "https://unifi",
		},
	}, nil
}

func (*MockClient) GetClients(_ []*unifi.Site) ([]*unifi.Client, error) {
	return []*unifi.Client{
		{
			ID:         "abcdef0123456789abcdef01",
			Name:       "host1",
			SiteName:   "Default (default)",
			SourceName: "https://unifi",
			Hostname:   "parsable.example.com",
			IP:         "192.168.1.1",
		},
		{
			ID:         "abcdef0123456789abcdef02",
			Name:       "host2",
			SiteName:   "Default (default)",
			SourceName: "https://unifi",
			Hostname:   "not valid as a host",
			IP:         "192.168.1.2",
		},
	}, nil
}
