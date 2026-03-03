package spec

import "testing"

func TestValidName(t *testing.T) {
	valid := []string{
		"ab",
		"foo",
		"BAR",
		"a-b-c",
		"vrf-r255",
		"tlog-witness",
		"static-ct-api",
		"age",
		"AGE",
		"a1",
		"1a",
		"A1",
		"abc123",
		"ABC123",
	}
	for _, name := range valid {
		if !ValidName(name) {
			t.Errorf("ValidName(%q) = false, want true", name)
		}
	}

	invalid := []string{
		"",          // too short
		"a",         // too short
		"A",         // too short
		"-",         // too short, starts with hyphen
		"1",         // too short
		"12",        // only digits
		"1-2",       // only digits and hyphens
		"-foo",      // starts with hyphen
		"foo-",      // ends with hyphen
		"foo--bar",  // consecutive hyphens
		"foo.bar",   // contains dot
		"foo_bar",   // contains underscore
		"foo..bar",  // contains dot
		"fOo",       // mixed case
		"Foo",       // mixed case
		"FOo",       // mixed case
		"foo bar",   // contains space
		"foo/bar",   // contains slash
		"foo@bar",   // contains at sign
		"123-456",   // only digits and hyphens
		"1-2-3-4-5", // only digits and hyphens
	}
	for _, name := range invalid {
		if ValidName(name) {
			t.Errorf("ValidName(%q) = true, want false", name)
		}
	}
}

func TestValidVersion(t *testing.T) {
	valid := []string{
		"v0.0.1",
		"v1.0.0",
		"v1.0.1-pre.1",
		"v2.3.4",
		"v0.1.0-alpha",
	}
	for _, v := range valid {
		if !ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = false, want true", v)
		}
	}

	invalid := []string{
		"",
		"1.0.0",     // missing v prefix
		"v1",        // not canonical
		"v1.0",      // not canonical
		"v01.0.0",   // leading zero
		"v1.0.0.0",  // too many parts
		"notaversion",
	}
	for _, v := range invalid {
		if ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = true, want false", v)
		}
	}
}
