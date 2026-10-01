package linkcheck

import (
	"strings"
	"testing"

	"c2sp.org/C2SP/.github/speclint"
)

func TestUndefinedReferencesAreNormalLint(t *testing.T) {
	src := testSpec("consumer", "# Consumer\n\n[dependency][missing]\n\nA note[^absent].\n")
	got := speclint.Check("consumer", []byte(src))
	if len(got) != 2 {
		t.Fatalf("expected normal reference and footnote errors, got %+v", got)
	}
	for _, d := range got {
		if !strings.Contains(d.Message, "undefined") || strings.Contains(d.Message, "release") {
			t.Fatalf("undefined reference treated as release-only: %+v", got)
		}
	}
	src = testSpec("consumer", "# Consumer\n\n[dependency][found]\n\nA note[^present].\n\n"+
		"[found]: #consumer\n\n[^present]: Defined note.\n")
	if got := speclint.Check("consumer", []byte(src)); len(got) != 0 {
		t.Fatalf("defined references rejected: %+v", got)
	}
}

func TestUndefinedReferencesInProjectDocuments(t *testing.T) {
	r := newRepo(t)
	r.write("consumer.md", "# Consumer\n")
	base := r.commit()
	r.write(".github/MANUAL.md", "# Manual\n\n[missing][]\n")
	got := r.check(base)
	if len(got) != 1 || got[0].Existing || got[0].File != ".github/MANUAL.md" || got[0].Line != 3 {
		t.Fatalf("undefined project reference not checked normally: %+v", got)
	}
}

func TestUndefinedReferencesAtSelectedReleaseCommit(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("consumer.md", "# Consumer\n\n[dependency][missing]\n")
	recorded := r.commit()
	r.write("consumer.md", "# Consumer\n\nFixed on main.\n")
	r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
	r.commit()
	got := r.check("HEAD")
	if len(got) != 1 || got[0].Existing || !strings.Contains(got[0].Message, "consumer@v1.0.0") {
		t.Fatalf("normal reference check skipped proposed release source: %+v", got)
	}
}

func TestOldTagsNotSubjectToNewSourceLinters(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("consumer.md", "# Consumer\n\n[dependency][missing]\n")
	recorded := r.commit()
	r.git("tag", "consumer/v0.1.0")
	r.write("consumer.md", "# Consumer\n\nFixed on main.\n")
	r.commit()
	assertClean(t, r.check(""))
	// Reusing the same source for a new release does run today's linters.
	r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
	r.commit()
	got := r.check("HEAD")
	if len(got) != 1 || got[0].Existing || !strings.Contains(got[0].Message, "consumer@v1.0.0") {
		t.Fatalf("new release was exempted because the blob was previously published: %+v", got)
	}
}
