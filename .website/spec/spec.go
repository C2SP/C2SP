// Package spec provides validation functions for C2SP spec names and versions.
package spec

import "golang.org/x/mod/semver"

// ValidName reports whether name is a valid C2SP spec name.
//
// A valid spec name must:
//   - be at least two characters long
//   - contain only ASCII alphanumeric characters and hyphens
//   - not start or end with a hyphen
//   - not contain consecutive hyphens
//   - be either all uppercase or all lowercase
//   - contain at least one letter
func ValidName(name string) bool {
	if len(name) < 2 {
		return false
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	hasLower, hasUpper, hasLetter := false, false, false
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
			hasLetter = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
			hasLetter = true
		case c >= '0' && c <= '9':
			// ok
		case c == '-':
			if i > 0 && name[i-1] == '-' {
				return false
			}
		default:
			return false
		}
	}
	if !hasLetter {
		return false
	}
	if hasLower && hasUpper {
		return false
	}
	return true
}

// ValidVersion reports whether v is a valid C2SP spec version.
//
// A valid version is a canonical semantic version string, such as "v1.0.0".
func ValidVersion(v string) bool {
	return v != "" && semver.Canonical(v) == v
}
