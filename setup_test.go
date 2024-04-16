package tailscale

import (
	"context"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/miekg/dns"
)

func (o *options) equals(other options) bool {
	return o.aaaa == other.aaaa &&
		o.reload == other.reload &&
		o.ttl == other.ttl &&
		o.enableFullName == other.enableFullName &&
		o.caseSensitive == other.caseSensitive
}

type nopPlugin struct{}

func (h *nopPlugin) Name() string { return "nop" }

func (h *nopPlugin) ServeDNS(_ context.Context, _ dns.ResponseWriter, _ *dns.Msg) (int, error) {
	return 0, nil
}
func TestHostParse(t *testing.T) {
	// need to implement mocking
	f := fall.F{}
	f.SetZonesFromArgs([]string{"example.com", "example.org"})
	tests := []struct {
		description string
		input       string
		wantErr     bool
		wantOptions options
	}{
		{
			description: `all parameters are present`,
			input: `
   tailscale ruinscorocoro@gmail.com tskey-api-kcpzy2Y5jK11CNTRL-A2M8gSQDk9h38jSstKAADhVMpUMVr744 {
          fullname
          fallthrough
}`,
			wantOptions: options{
				aaaa:           true,
				reload:         1 * time.Second,
				ttl:            60,
				caseSensitive:  true,
				enableFullName: true,
				tailnet:        "example-ts.net",
				token:          "0123deafbeaf",
				fall:           f,
			},
		},
		{
			description: `only mandatory arguments are present`,
			input: `
tailscale a.example-ts.net password`,
			wantOptions: options{
				tailnet: "example-ts.net",
				token:   "0123deafbeaf",
				// defaults
				reload:         60 * time.Second,
				ttl:            60,
				caseSensitive:  false,
				enableFullName: true,
			},
		},
		{
			description: `missing mandatory arguments`,
			input:       `tailscale`,
			wantErr:     true,
		},
		{
			description: `malformed arbitrary argument`,
			input: `
tailscale example-ts.net 0123deadbeaf {
    wrong
}`,
			wantErr: true,
		},
		{
			description: `missing mandatory arguments`,
			input:       `tailscale`,
			wantErr:     true,
		},
	}

	for _, test := range tests {
		c := caddy.NewTestController("nop", test.input)
		h, err := hostsParse(c)

		got := h.options
		want := test.wantOptions
		desc := test.description
		if err == nil && test.wantErr {
			t.Fatalf("Test `%s` expected errors, but got no error", desc)
		} else if err != nil && !test.wantErr {
			t.Fatalf("Test `%s` expected no errors, but got '%v'", desc, err)
		} else {
			if !test.wantErr && !got.equals(want) {
				t.Fatalf("Test `%s` expected options to be '%v', but got '%v'", desc, want, got)
			}
		}
	}
}
