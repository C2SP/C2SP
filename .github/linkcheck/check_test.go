package linkcheck

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type testRepo struct {
	t           *testing.T
	root        string
	formatSpecs bool
}

func newRepo(t *testing.T) *testRepo {
	t.Helper()
	r := &testRepo{t: t, root: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.git("config", "user.email", "test@example.com")
	r.git("config", "user.name", "Test")
	return r
}

// Release fixtures must satisfy the current format lints as well as link checks.
// Ordinary graph tests deliberately keep their small source/line-number fixtures.
func newReleaseRepo(t *testing.T) *testRepo {
	r := newRepo(t)
	r.formatSpecs = true
	return r
}

const specPreambleLines = 8

func testSpec(name, body string) string {
	return fmt.Sprintf("---\ndescription: Test spec\n---\n\n"+
		"> [!WARNING]\n> This is the editor's copy of this specification.\n"+
		"> For a stable rendered reference, use [c2sp.org/%s](https://c2sp.org/%s).\n\n%s",
		name, name, body)
}

func (r *testRepo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.root}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *testRepo) write(p, data string) {
	r.t.Helper()
	if r.formatSpecs && strings.HasSuffix(p, ".md") && !strings.Contains(p, "/") &&
		!strings.HasPrefix(data, "---\n") {
		data = testSpec(strings.TrimSuffix(p, ".md"), data)
	}
	p = filepath.Join(r.root, filepath.FromSlash(p))
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *testRepo) commit() string {
	r.t.Helper()
	r.git("add", ".")
	r.git("commit", "-qm", "snapshot", "--allow-empty")
	return r.git("rev-parse", "HEAD")
}

func (r *testRepo) check(base string) []Diagnostic {
	r.t.Helper()
	got, err := Check(r.root, base)
	if err != nil {
		r.t.Fatal(err)
	}
	return got
}

func assertClean(t *testing.T, got []Diagnostic) {
	t.Helper()
	if len(got) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", got)
	}
}

func hasMessage(t *testing.T, got []Diagnostic, substring string, existing bool) {
	t.Helper()
	for _, d := range got {
		if strings.Contains(d.Message, substring) && d.Existing == existing {
			return
		}
	}
	t.Fatalf("no diagnostic containing %q with Existing=%v: %+v", substring, existing, got)
}

func TestPinnedAndFloating(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n## Old\n")
	r.commit()
	r.git("tag", "producer/v1.0.0")
	r.write("producer.md", "# Producer\n\n## New\n")
	r.write("consumer.md", "# Consumer\n\n[pin](https://c2sp.org/producer@v1.0.0#old)\n[main](https://c2sp.org/producer@main#new)\n")
	r.commit()
	assertClean(t, r.check(""))
	r.write("consumer.md", "# Consumer\n\n[future](https://c2sp.org/producer#old)\n[current](https://c2sp.org/producer@latest#new)\n")
	got := r.check("")
	hasMessage(t, got, "missing anchor #old", false)
	hasMessage(t, got, "missing anchor #new", false)
	hasMessage(t, got, "If this section was renamed", false)
}

func TestRenameReferencedOnlyFromOldRelease(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n## Old\n")
	r.write("consumer.md", "# Consumer\n\n[reference](https://c2sp.org/producer@main#old)\n")
	r.commit()
	r.git("tag", "consumer/v1.0.0")
	r.write("consumer.md", "# Consumer\n\nNo longer links.\n")
	base := r.commit()
	r.write("producer.md", "# Producer\n\n## New\n")
	got := r.check(base)
	if len(got) != 1 || got[0].File != "producer.md" || got[0].Existing {
		t.Fatalf("expected one destination regression: %+v", got)
	}
	hasMessage(t, got, "consumer@v1.0.0:3", false)
	hasMessage(t, got, `id="old"`, false)
	r.write("producer.md", "# Producer\n\n<a id=\"old\"></a>\n\n## New\n")
	assertClean(t, r.check(base))
}

func TestBaselineDebtAndNewCopies(t *testing.T) {
	r := newRepo(t)
	r.write("consumer.md", "# Consumer\n\n[bad](https://c2sp.org/absent@main#typo)\n\nText.\n")
	base := r.commit()
	r.write("consumer.md", "# Consumer\n\nIntroduction.\n\n[bad](https://c2sp.org/absent@main#typo)\n\nText.\n\n[bad](https://c2sp.org/absent@main#typo)\n")
	got := r.check(base)
	if len(got) != 2 {
		t.Fatalf("expected old occurrence and new copy: %+v", got)
	}
	if !got[0].Existing || got[0].Line != 5 || got[1].Existing || got[1].Line != 9 {
		t.Fatalf("diff line grandfathering: %+v", got)
	}
	full := r.check("")
	for _, d := range full {
		if d.Existing {
			t.Fatalf("full audit grandfathered a failure: %+v", d)
		}
	}
}

func TestHistoricalDebtAndNewHistoricalRegression(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n## Old\n")
	r.write("consumer.md", "# Consumer\n\n[typo](https://c2sp.org/producer@main#typo)\n[old](https://c2sp.org/producer@main#old)\n")
	r.commit()
	r.git("tag", "consumer/v1.0.0")
	r.write("consumer.md", "# Consumer\n")
	base := r.commit()
	r.write("producer.md", "# Producer\n\n## New\n")
	got := r.check(base)
	hasMessage(t, got, "missing anchor #typo", true)
	hasMessage(t, got, "removed anchor #old", false)
}

func TestVersions(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		want string
	}{
		{"no tags", nil, "main"},
		{"prerelease only", []string{"v1.0.0-beta.2", "v1.0.0-beta.1"}, "v1.0.0-beta.2"},
		{"stable priority", []string{"v2.0.0-beta.1", "v1.0.0"}, "v1.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRepo(t)
			for _, tag := range tt.tags {
				r.write("producer.md", "# Producer\n\n<a id=\""+tag+"\"></a>\n\n## Release\n")
				r.commit()
				r.git("tag", "producer/"+tag)
			}
			r.write("producer.md", "# Producer\n\n## main\n")
			r.write("consumer.md", "# Consumer\n\n[bare](https://c2sp.org/producer#"+tt.want+")\n[latest](https://c2sp.org/producer@latest#"+tt.want+")\n")
			r.commit()
			got := r.check("")
			// Released anchors absent from main impose a future requirement.
			if tt.want == "main" {
				assertClean(t, got)
			} else {
				for _, d := range got {
					if strings.Contains(d.Message, "current resolution") {
						t.Fatalf("latest selection wrong: %+v", got)
					}
				}
				hasMessage(t, got, "future release", false)
			}
		})
	}
}

func TestTaggedLocalLinksAreOwnRevision(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n[local](#old)\n\n## Old\n")
	r.commit()
	r.git("tag", "producer/v1.0.0")
	r.write("producer.md", "# Producer\n\n## New\n")
	r.commit()
	assertClean(t, r.check(""))
}

func TestDeletedFilesAndMissingRefs(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n## Old\n")
	r.write("consumer.md", "# Consumer\n\n[main](https://c2sp.org/producer@main#old)\n")
	base := r.commit()
	if err := os.Remove(filepath.Join(r.root, "producer.md")); err != nil {
		t.Fatal(err)
	}
	got := r.check(base)
	hasMessage(t, got, "missing document producer.md", false)
	for _, d := range got {
		if strings.Contains(d.Message, "<a id=") {
			t.Fatalf("alias suggestion for deleted file: %+v", d)
		}
	}
	r.write("consumer.md", "# Consumer\n\n[tag](https://c2sp.org/producer@v9.0.0#old)\n[commit](https://c2sp.org/producer@abcdef0#old)\n")
	got = r.check(base)
	hasMessage(t, got, "missing version producer@v9.0.0", false)
	hasMessage(t, got, "missing commit", false)
}

func TestTagWithMissingMatchingFile(t *testing.T) {
	r := newRepo(t)
	r.write("unrelated.md", "# Unrelated\n")
	r.commit()
	r.git("tag", "missing/v1.0.0")
	base := r.commit()
	got := r.check(base)
	hasMessage(t, got, "missing document missing.md", true)
}

func TestOnlyMatchingSpecIsReadAtTags(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n")
	r.write("unrelated.md", "# Unrelated\n\n[bad](https://c2sp.org/missing)\n")
	r.commit()
	r.git("tag", "producer/v1.0.0")
	r.write("unrelated.md", "# Unrelated\n")
	r.commit()
	assertClean(t, r.check(""))
}

func TestProjectRoutesAndEncodedLinks(t *testing.T) {
	r := newRepo(t)
	r.write(".github/MANUAL.md", "# Manual\n\n## café\n\n<a id=\"a+b\"></a>\n")
	r.write("producer.md", "# Producer\n\n[manual](https://c2sp.org/-/manual#caf%C3%A9)\n[plus](https://c2sp.org/-/manual#a+b)\n[project](https://c2sp.org/-/manual)\n[external](https://example.com/nope#bad)\n[ignored](https://c2sp.org/CCTV/foo)\n")
	r.commit()
	assertClean(t, r.check(""))
}

func TestProblemsAndAliases(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n<a id=\"alias\"></a>\n<a id=\"second\"></a>\n\n## Actual\n\n[one](#alias)\n[two](#second)\n\n```html\n<a id=\"fake\"></a>\n[bad](https://c2sp.org/does-not-exist)\n```\n")
	base := r.commit()
	assertClean(t, r.check(base))
	r.write("producer.md", "# Producer\n\n<a id=\"actual\"></a>\n\n## Actual\n")
	got := r.check(base)
	hasMessage(t, got, "anchor", false)
}

func TestCommitSnapshotReachabilityAndOutgoingLinks(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n## Old\n")
	old := r.commit()
	r.write("producer.md", "# Producer\n\n## New\n")
	r.write("consumer.md", "# Consumer\n\n[old](https://c2sp.org/producer@"+old[:12]+"#old)\n")
	r.commit()
	assertClean(t, r.check(""))
	// A detached side branch object exists, but is not an ancestor of main.
	r.git("checkout", "-qb", "side", old)
	r.write("producer.md", "# Producer\n\n## Side\n")
	side := r.commit()
	r.git("checkout", "-q", "main")
	r.write("consumer.md", "# Consumer\n\n[side](https://c2sp.org/producer@"+side+"#side)\n")
	hasMessage(t, r.check(""), "not reachable from main", false)
}

func TestCommitSnapshotOutgoingLinks(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n[bad](https://c2sp.org/missing)\n")
	old := r.commit()
	r.write("producer.md", "# Producer\n")
	r.write("consumer.md", "# Consumer\n\n[old](https://c2sp.org/producer@"+old+")\n")
	r.commit()
	got := r.check("")
	hasMessage(t, got, "producer@"+old, false)
	hasMessage(t, got, "missing document missing.md", false)
}

func TestProposalsCannotRepairCurrentLinks(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n\n## New\n")
	old := r.commit()
	r.write("producer/.new-tag", "v1.0.0\n"+old+"\n")
	r.write("consumer.md", "# Consumer\n\n[pin](https://c2sp.org/producer@v1.0.0#new)\n")
	r.commit()
	got := r.check("")
	hasMessage(t, got, "missing version producer@v1.0.0", false)
	for _, d := range got {
		if strings.Contains(d.Message, "after proposed tags") && strings.Contains(d.Message, "missing version") {
			t.Fatalf("proposed pin was not available virtually: %+v", got)
		}
	}
}

func TestProposedOldCommitChangesLatest(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n\n## Old\n")
	old := r.commit()
	r.write("producer.md", "# Producer\n\n## New\n")
	r.write("consumer.md", "# Consumer\n\n[latest](https://c2sp.org/producer#new)\n")
	base := r.commit()
	r.write("producer/.new-tag", "v1.0.0\n"+old+"\n")
	got := r.check(base)
	hasMessage(t, got, "after proposed tags", false)
	hasMessage(t, got, "missing anchor #new", false)
	// Without the proposal, no tags means candidate main is latest.
	if err := os.Remove(filepath.Join(r.root, "producer/.new-tag")); err != nil {
		t.Fatal(err)
	}
	assertClean(t, r.check(base))
}

func TestProposedOldCommitOutgoingLinks(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n\n[broken](https://c2sp.org/missing@main)\n")
	old := r.commit()
	r.write("producer.md", "# Producer\n")
	base := r.commit()
	r.write("producer/.new-tag", "v1.0.0\n"+old+"\n")
	hasMessage(t, r.check(base), "after proposed tags", false)
}

func TestInvalidProposals(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n")
	commit := r.commit()
	for _, data := range []string{
		"v1\n" + commit + "\n",
		"v1.0.0\n" + commit[:12] + "\n",
		"v1.0.0\n" + strings.Repeat("f", 40) + "\n",
	} {
		r.write("producer/.new-tag", data)
		if got := r.check(""); len(got) == 0 {
			t.Fatalf("invalid proposal accepted: %q", data)
		}
	}
}

func TestProposalUnreachableCommit(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n")
	main := r.commit()
	r.git("checkout", "-qb", "side")
	r.write("producer.md", "# Producer\n\n## Side\n")
	side := r.commit()
	r.git("checkout", "-q", "main")
	r.write("producer/.new-tag", "v1.0.0\n"+side+"\n")
	hasMessage(t, r.check(main), "not reachable from main", false)
}

func TestProposalMissingFile(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n")
	old := r.commit()
	r.write("missing/.new-tag", "v1.0.0\n"+old+"\n")
	got := r.check(old)
	hasMessage(t, got, "missing document missing.md", false)
	for _, d := range got {
		if d.File != "missing/.new-tag" || d.Line != 2 {
			t.Fatalf("bad proposal-file annotation: %+v", got)
		}
	}
}

func TestCommittedProposalIsNotGrandfathered(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n\n## Old\n")
	old := r.commit()
	r.write("producer.md", "# Producer\n\n## New\n")
	r.write("consumer.md", "# Consumer\n\n[latest](https://c2sp.org/producer#new)\n")
	r.write("producer/.new-tag", "v1.0.0\n"+old+"\n")
	base := r.commit()
	r.write("unrelated.md", "# Unrelated\n")
	got := r.check(base)
	hasMessage(t, got, "after proposed tags", false)
	for _, d := range got {
		if d.Existing {
			t.Fatalf("committed proposed-release failure was grandfathered: %+v", got)
		}
	}
	hasMessage(t, r.check("HEAD"), "after proposed tags", false)
}

func TestCommittedInvalidProposalIsNotGrandfathered(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n")
	r.write("producer/.new-tag", "v1.0.0\nbad-commit\n")
	r.commit()
	hasMessage(t, r.check("HEAD"), "invalid .new-tag commit", false)
}

func TestProposalDoesNotDuplicateCurrentDebt(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n")
	commit := r.commit()
	r.write("consumer.md", "# Consumer\n\n[broken](https://c2sp.org/producer#typo)\n")
	r.write("producer/.new-tag", "v1.0.0\n"+commit+"\n")
	r.commit()
	got := r.check("HEAD")
	if len(got) != 1 || !got[0].Existing || strings.Contains(got[0].Message, "after proposed tags") {
		t.Fatalf("proposal duplicated unchanged current debt: %+v", got)
	}
}

func TestDuplicateProblemIdentityIgnoresFirstDefinitionLine(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n<a id=\"duplicate\"></a>\n<a id=\"duplicate\"></a>\n")
	base := r.commit()
	r.write("producer.md", "# Producer\n\nIntroduction.\n\n<a id=\"duplicate\"></a>\n<a id=\"duplicate\"></a>\n")
	got := r.check(base)
	if len(got) != 1 || !got[0].Existing {
		t.Fatalf("unchanged duplicate became new because its first definition moved: %+v", got)
	}
	hasMessage(t, got, "first defined on line 5", true)
}

func TestGroupedReferrersAndDestinationLine(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n## Old\n\nFollowing text.\n")
	r.write("consumer.md", "# Consumer\n\n[one](https://c2sp.org/producer@main#old)\n[two](https://c2sp.org/producer@main#old)\n")
	base := r.commit()
	r.write("producer.md", "# Producer\n\n## New\n\nFollowing text.\n")
	got := r.check(base)
	if len(got) != 1 || got[0].File != "producer.md" || got[0].Line < 3 {
		t.Fatalf("expected a single changed-destination annotation: %+v", got)
	}
	hasMessage(t, got, "consumer.md:3", false)
	hasMessage(t, got, "consumer.md:4", false)
}

func TestAliasRemovalAndPinnedReferences(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n<a id=\"old\"></a>\n\n## New\n")
	r.commit()
	r.git("tag", "producer/v1.0.0")
	r.write("consumer.md", "# Consumer\n\n[pin](https://c2sp.org/producer@v1.0.0#old)\n")
	base := r.commit()
	r.write("producer.md", "# Producer\n\n## New\n")
	assertClean(t, r.check(base))
	r.write("consumer.md", "# Consumer\n\n[main](https://c2sp.org/producer@main#old)\n")
	hasMessage(t, r.check(base), "removed anchor #old", false)
}

func TestInvalidRouteDiagnostics(t *testing.T) {
	r := newRepo(t)
	r.write("consumer.md", "# Consumer\n\n[version](https://c2sp.org/producer@banana#x)\n[route](https://c2sp.org/-/unknown#x)\n[valid pin](https://c2sp.org/producer@v1.0.0#x)\n")
	r.commit()
	got := r.check("")
	hasMessage(t, got, "invalid C2SP version", false)
	hasMessage(t, got, "invalid C2SP document path", false)
	hasMessage(t, got, "missing version", false)
}

func TestProjectSourcesAndLocalLinks(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n## Section\n")
	r.write(".github/MANUAL.md", "# Manual\n\n[local](#manual)\n[spec](https://c2sp.org/producer@main#section)\n")
	base := r.commit()
	assertClean(t, r.check(base))
	r.write(".github/MANUAL.md", "# Manual\n\n[bad](https://c2sp.org/producer@main#typo)\n")
	got := r.check(base)
	if len(got) != 1 || got[0].File != ".github/MANUAL.md" || got[0].Line != 3 {
		t.Fatalf("project source location lost: %+v", got)
	}
}

func TestMissingProjectDestination(t *testing.T) {
	r := newRepo(t)
	r.write("consumer.md", "# Consumer\n\n[manual](https://c2sp.org/-/manual#section)\n")
	r.commit()
	hasMessage(t, r.check(""), "missing document .github/MANUAL.md", false)
}

func TestSunlightRedirect(t *testing.T) {
	r := newRepo(t)
	r.write("static-ct-api.md", "# Static CT API\n\n## Section\n")
	r.write("consumer.md", "# Consumer\n\n[legacy](https://c2sp.org/sunlight#section)\n")
	r.commit()
	assertClean(t, r.check(""))
}

func TestShallowRejected(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n")
	r.commit()
	r.commit()
	clone := filepath.Join(t.TempDir(), "clone")
	r.git("clone", "-q", "--depth=1", "file://"+r.root, clone)
	_, err := Check(clone, "")
	if err == nil || !strings.Contains(err.Error(), "non-shallow") {
		t.Fatalf("shallow repo accepted: %v", err)
	}
}

func TestPartialCloneConfigurationRejectedBeforeObjectReads(t *testing.T) {
	tests := []struct {
		key, value string
	}{
		{"remote.origin.promisor", "true"},
		{"remote.origin.promisor", "yes"},
		{"remote.other.promisor", "on"},
		{"remote.other.promisor", "1"},
		{"extensions.partialclone", "origin"},
	}
	for _, tt := range tests {
		t.Run(tt.key+"="+tt.value, func(t *testing.T) {
			r := newRepo(t)
			r.write("producer.md", "# Producer\n")
			r.commit()
			blob := r.git("rev-parse", "HEAD:producer.md")
			// A missing object would make fsck fail, or a partial clone try
			// lazy-fetching. Reject the configuration before inspecting it.
			if err := os.Remove(filepath.Join(r.root, ".git", "objects", blob[:2], blob[2:])); err != nil {
				t.Fatal(err)
			}
			r.git("config", tt.key, tt.value)
			_, err := Check(r.root, "")
			if err == nil || !strings.Contains(err.Error(), "full clone") || !strings.Contains(err.Error(), tt.key) {
				t.Fatalf("partial clone was not rejected before object access: %v", err)
			}
		})
	}
}

func TestEffectivePromisorConfigurationRejected(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n")
	r.commit()
	// Effective configuration includes command/environment-level overrides,
	// not just the repository's config file.
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "remote.synthetic.promisor")
	t.Setenv("GIT_CONFIG_VALUE_0", "true")
	_, err := Check(r.root, "")
	if err == nil || !strings.Contains(err.Error(), "full clone") {
		t.Fatalf("effective promisor configuration was ignored: %v", err)
	}
}

func TestFalsePromisorConfigurationAllowed(t *testing.T) {
	for _, value := range []string{"false", "no", "off", "0", ""} {
		t.Run(value, func(t *testing.T) {
			r := newRepo(t)
			r.write("producer.md", "# Producer\n")
			r.commit()
			r.git("config", "remote.origin.promisor", value)
			assertClean(t, r.check(""))
		})
	}
}

func TestWorkingTreeSourceSymlinkRejected(t *testing.T) {
	r := newRepo(t)
	r.write("consumer.md", "# Consumer\n\n[valid target](https://c2sp.org/producer@main#section)\n")
	r.commit()
	target := filepath.Join(t.TempDir(), "valid.md")
	if err := os.WriteFile(target, []byte("# Producer\n\n## Section\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(r.root, "producer.md")); err != nil {
		t.Fatal(err)
	}
	_, err := Check(r.root, "HEAD")
	if err == nil || !strings.Contains(err.Error(), "symlink") || !strings.Contains(err.Error(), "producer.md") {
		t.Fatalf("working-tree Markdown symlink was followed: %v", err)
	}
}

func TestProjectDocumentSymlinksRejected(t *testing.T) {
	for _, component := range []string{".github", ".github/MANUAL.md"} {
		t.Run(component, func(t *testing.T) {
			r := newRepo(t)
			r.write("producer.md", "# Producer\n")
			r.commit()
			targetDir := t.TempDir()
			target := filepath.Join(targetDir, "MANUAL.md")
			if err := os.WriteFile(target, []byte("# Manual\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if component == ".github" {
				target = targetDir
			} else if err := os.Mkdir(filepath.Join(r.root, ".github"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(r.root, component)); err != nil {
				t.Fatal(err)
			}
			_, err := Check(r.root, "")
			if err == nil || !strings.Contains(err.Error(), "symlink") || !strings.Contains(err.Error(), component) {
				t.Fatalf("project source symlink was followed or silently skipped: %v", err)
			}
		})
	}
}

func TestNonRegularWorkingTreeSourceRejected(t *testing.T) {
	r := newRepo(t)
	r.write("consumer.md", "# Consumer\n")
	r.commit()
	if err := os.Mkdir(filepath.Join(r.root, "producer.md"), 0755); err != nil {
		t.Fatal(err)
	}
	_, err := Check(r.root, "")
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("nonregular source was silently excluded: %v", err)
	}
}

func TestProposalSourceSymlinkRejected(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n")
	commit := r.commit()
	target := filepath.Join(t.TempDir(), "proposal")
	if err := os.WriteFile(target, []byte("v1.0.0\n"+commit+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(r.root, "producer"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(r.root, "producer", ".new-tag")); err != nil {
		t.Fatal(err)
	}
	_, err := Check(r.root, "")
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("proposal symlink was followed: %v", err)
	}
}

func TestTrackedProposalSymlinkDirectoryRejected(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n")
	commit := r.commit()
	r.write("producer/.new-tag", "v1.0.0\n"+commit+"\n")
	r.commit()
	target := filepath.Join(t.TempDir(), "proposal-dir")
	if err := os.Rename(filepath.Join(r.root, "producer"), target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(r.root, "producer")); err != nil {
		t.Fatal(err)
	}
	_, err := Check(r.root, "HEAD")
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("tracked proposal disappeared behind a symlink directory: %v", err)
	}
}

func TestProposalThroughTrackedSymlinkToHiddenDirectoryRejected(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer.md", "# Producer\n\n[broken](https://c2sp.org/missing@main)\n")
	old := r.commit()
	r.write("producer.md", "# Producer\n")
	r.write(".github/proposal-data/.new-tag", "v1.0.0\n"+old+"\n")
	if err := os.Symlink(".github/proposal-data", filepath.Join(r.root, "producer")); err != nil {
		t.Fatal(err)
	}
	r.commit()
	// The index contains the parent symlink and the hidden real proposal,
	// but not producer/.new-tag. The tag creator's glob still discovers it.
	matches, err := filepath.Glob(filepath.Join(r.root, "*", ".new-tag"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("creator would not discover the proposal: %v, %v", matches, err)
	}
	if _, err := ProposalPaths(r.root); err == nil || !strings.Contains(err.Error(), "symlink component producer") {
		t.Fatalf("shared proposal discovery accepted a symlink parent: %v", err)
	}
	_, err = Check(r.root, "HEAD")
	if err == nil || !strings.Contains(err.Error(), "symlink component producer") {
		t.Fatalf("release preflight ignored a proposal discovered by create-tag: %v", err)
	}
}

func TestProposalPathsAreRootRelative(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("producer/.new-tag", "proposal contents are not read\n")
	r.write("consumer/.new-tag", "proposal contents are not read\n")
	r.write(".github/nested/.new-tag", "not a creator proposal\n")
	got, err := ProposalPaths(r.root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "consumer/.new-tag,producer/.new-tag" {
		t.Fatalf("proposal discovery did not return sorted root-relative creator paths: %v", got)
	}
}

func TestUnchangedLineMapping(t *testing.T) {
	tests := []struct {
		old, new string
		want     map[int]int
	}{
		{"a\nb\n", "a\nb\n", map[int]int{1: 1, 2: 2}},
		{"a\nb\n", "new\na\nb\n", map[int]int{2: 1, 3: 2}},
		{"a\nb\nc\n", "a\nnew\nc\n", map[int]int{1: 1, 3: 3}},
		{"a\nb\nc\n", "a\nc\n", map[int]int{1: 1, 2: 3}},
		{"a\n", "a\nnew\n", map[int]int{1: 1}},
	}
	for _, tt := range tests {
		got, err := unchangedLines([]byte(tt.old), []byte(tt.new))
		if err != nil {
			t.Fatal(err)
		}
		for line, old := range tt.want {
			if got[line] != old {
				t.Errorf("mapping %q -> %q: %d -> %d, want %d", tt.old, tt.new, line, got[line], old)
			}
		}
	}
}
