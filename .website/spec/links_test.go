package spec

import (
	"reflect"
	"testing"
)

func TestLatestVersion(t *testing.T) {
	tests := []struct {
		versions []string
		want     string
	}{
		{nil, ""},
		{[]string{"v2.0.0-rc.1", "v1.2.0", "v1.0.0"}, "v1.2.0"},
		{[]string{"v1.0.0-rc.2", "v1.0.0-rc.1"}, "v1.0.0-rc.2"},
		{[]string{"invalid", "v0.0.1"}, "v0.0.1"},
		{[]string{"v1.0.0+z", "v1.0.0+a", "v1"}, "v1.0.0+z"},
	}
	for _, tt := range tests {
		if got := LatestVersion(tt.versions); got != tt.want {
			t.Errorf("LatestVersion(%q) = %q, want %q", tt.versions, got, tt.want)
		}
	}
}

func TestParseLink(t *testing.T) {
	tests := []struct {
		dest, source string
		want         Target
		bad          bool
	}{
		{"https://c2sp.org/foo#bar", "/other", Target{Path: "foo.md", Name: "foo", Version: "latest", Fragment: "bar"}, false},
		{"https://c2sp.org/foo@main#Bar", "/other", Target{Path: "foo.md", Name: "foo", Version: "main", Fragment: "Bar"}, false},
		{"/foo@latest#bar", "/other", Target{Path: "foo.md", Name: "foo", Version: "latest", Fragment: "bar"}, false},
		{"//C2SP.ORG/foo@v1.0.0#%C3%A9%2B%20x", "/other", Target{Path: "foo.md", Name: "foo", Version: "v1.0.0", Fragment: "é+ x"}, false},
		{"#A+B", "/foo@v1.0.0", Target{Path: "foo.md", Name: "foo", Version: "v1.0.0", Fragment: "A+B", Local: true}, false},
		{"#%2520", "/foo@main", Target{Path: "foo.md", Name: "foo", Version: "main", Fragment: "%20", Local: true}, false},
		{"#", "/foo@main", Target{Path: "foo.md", Name: "foo", Version: "main", Local: true}, false},
		{"/sunlight#log-entries", "/other", Target{Path: "static-ct-api.md", Name: "static-ct-api", Version: "latest", Fragment: "log-entries"}, false},
		{"/sunlight@main#log-entries", "/other", Target{Path: "sunlight.md", Name: "sunlight", Version: "main", Fragment: "log-entries"}, false},
		{"/foo@abcdef012345#bar", "/other", Target{Path: "foo.md", Name: "foo", Version: "abcdef012345", Fragment: "bar"}, false},
		{"#stewards", "/-/maintainers", Target{Path: ".github/MAINTAINERS.md", Version: "main", Fragment: "stewards", Local: true}, false},
		{"/-/manual#formatting", "/foo", Target{Path: ".github/MANUAL.md", Version: "main", Fragment: "formatting"}, false},
		{"/#specifications", "/foo", Target{Path: ".github/README.md", Version: "main", Fragment: "specifications"}, false},
		{"https://c2sp.org#specifications", "/foo", Target{Path: ".github/README.md", Version: "main", Fragment: "specifications"}, false},
		{"https://example.com/foo#bar", "/foo", Target{Ignore: true}, false},
		{"mailto:maintainers@example.com", "/foo", Target{Ignore: true}, false},
		{"/CCTV/age", "/foo", Target{Ignore: true}, false},
		{"/-/math/temml.css", "/foo", Target{Ignore: true}, false},
		{"/-/static/site.css", "/foo", Target{Ignore: true}, false},
		{"/foo?go-get=1", "/foo", Target{Ignore: true}, false},
		{"/foo?go-get=1#bar", "/foo", Target{}, true},
		{"/foo@bogus", "/foo", Target{}, true},
		{"/foo@", "/foo", Target{}, true},
		{"/foo/", "/foo", Target{}, true},
		{"/-/unknown", "/foo", Target{}, true},
		{"https://c2sp.org/foo#%ZZ", "/foo", Target{}, true},
		{"https:foo", "/foo", Target{}, true},
		{"https:///foo", "/foo", Target{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.dest, func(t *testing.T) {
			got, err := ParseLink(tt.dest, tt.source)
			if (err != nil) != tt.bad {
				t.Fatalf("ParseLink() error = %v, want error %v", err, tt.bad)
			}
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseLink() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
