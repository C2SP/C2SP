package linkcheck

import (
	"strings"
	"testing"
)

func TestReleaseChecksRecordedCommit(t *testing.T) {
	for _, version := range []string{"v1.0.0", "v0.1.0", "v1.0.0-rc.1"} {
		t.Run(version, func(t *testing.T) {
			r := newRepo(t)
			r.write("producer.md", "# Producer\n\n## Section\n")
			r.write("consumer.md", "# Consumer\n\n[dependency](https://c2sp.org/producer@main#section)\n")
			recorded := r.commit()
			// Fixing main does not fix the commit selected for publication.
			r.write("consumer.md", "# Consumer\n\nNo development link on main.\n")
			r.write("consumer/.new-tag", version+"\n"+recorded+"\n")
			r.commit()
			for _, base := range []string{"", "HEAD"} {
				got := r.check(base)
				if len(got) != 1 || got[0].Existing || got[0].File != "consumer.md" || got[0].Line != 3 {
					t.Fatalf("release preflight did not reject recorded source: %+v", got)
				}
				hasMessage(t, got, "consumer@"+version, false)
				hasMessage(t, got, "commit "+recorded, false)
				hasMessage(t, got, "must not link to @main", false)
			}
		})
	}
}

func TestReleasePolicyIsScopedToProposedSpec(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n## Section\n")
	r.write("consumer.md", "# Consumer\n\nReady for release.\n")
	// Another spec at the exact same commit is allowed development links.
	r.write("other.md", "# Other\n\n[dependency](https://c2sp.org/producer@main#section)\n")
	recorded := r.commit()
	r.git("tag", "other/v1.0.0")
	// Neither consumer's current main nor an existing published spec should
	// be subject to the new release policy.
	r.write("consumer.md", "# Consumer\n\n[development](https://c2sp.org/producer@main#section)\n")
	r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
	r.commit()
	assertClean(t, r.check(""))
	assertClean(t, r.check("HEAD"))
}

func TestReleaseMainLinkForms(t *testing.T) {
	tests := []struct {
		name, body string
	}{
		{"inline", "[dependency](https://c2sp.org/producer@main#section)"},
		{"reference", "[dependency][ref]\n\n[ref]: https://c2sp.org/producer@main#section"},
		{"autolink", "<https://c2sp.org/producer@main#section>"},
		{"bare autolink", "https://c2sp.org/producer@main#section"},
		{"html", `<a href="https://c2sp.org/producer@main#section">dependency</a>`},
		{"root relative", "[dependency](/producer@main#section)"},
		{"encoded", "[dependency](https://c2sp.org/producer%40main#section)"},
		{"no fragment", "[dependency](https://c2sp.org/producer@main)"},
		{"self reference", "[self](/consumer@main#consumer)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRepo(t)
			r.write("producer.md", "# Producer\n\n## Section\n")
			r.write("consumer.md", "# Consumer\n\n"+tt.body+"\n")
			recorded := r.commit()
			// Main-only development links remain valid before a release.
			assertClean(t, r.check(""))
			r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
			r.commit()
			got := r.check("HEAD")
			if len(got) != 1 || got[0].Existing {
				t.Fatalf("release @main link accepted: %+v", got)
			}
			hasMessage(t, got, "must not link to @main", false)
			if tt.name == "self reference" {
				hasMessage(t, got, "local #fragment", false)
			}
		})
	}
}

func TestReleasePolicyAllowsNonDevelopmentLinksAndExamples(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n## Section\n")
	dependency := r.commit()
	r.git("tag", "producer/v1.0.0")
	r.write(".github/MANUAL.md", "# Manual\n")
	r.write("consumer.md", "# Consumer\n\n"+
		"[pinned](https://c2sp.org/producer@v1.0.0#section)\n"+
		"[snapshot](https://c2sp.org/producer@"+dependency+"#section)\n"+
		"[latest](https://c2sp.org/producer@latest#section)\n"+
		"[bare](https://c2sp.org/producer#section)\n"+
		"[local](#consumer)\n"+
		"[project](https://c2sp.org/-/manual#manual)\n"+
		"[external](https://example.com/producer@main#section)\n"+
		"`[example](https://c2sp.org/producer@main#section)`\n\n"+
		"```markdown\n[example](https://c2sp.org/producer@main#section)\n```\n\n"+
		"<!-- [example](https://c2sp.org/producer@main#section) -->\n\n"+
		"[unused]: https://c2sp.org/producer@main#section\n")
	recorded := r.commit()
	r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
	r.commit()
	assertClean(t, r.check(""))
	assertClean(t, r.check("HEAD"))
}

func TestReleaseMainPolicyAppliesToEachProposal(t *testing.T) {
	r := newRepo(t)
	r.write("producer.md", "# Producer\n\n## Section\n")
	r.write("consumer.md", "# Consumer\n\n[dependency](https://c2sp.org/producer@main#section)\n")
	recorded := r.commit()
	// Releasing the dependency simultaneously does not make an explicit @main
	// link immutable or redirect it to the dependency's proposed release.
	r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
	r.write("producer/.new-tag", "v1.0.0\n"+recorded+"\n")
	r.commit()
	got := r.check("HEAD")
	if len(got) != 1 || got[0].Existing || !strings.Contains(got[0].Message, "consumer@v1.0.0") {
		t.Fatalf("release policy did not apply to the correct proposed spec: %+v", got)
	}
}

func TestReleaseRejectsImplicitMain(t *testing.T) {
	for _, version := range []string{"", "@latest"} {
		t.Run(version, func(t *testing.T) {
			r := newRepo(t)
			r.write("producer.md", "# Producer\n\n## Section\n")
			r.write("consumer.md", "# Consumer\n\n[dependency](https://c2sp.org/producer"+version+"#section)\n")
			recorded := r.commit()
			r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
			r.commit()
			got := r.check("HEAD")
			if len(got) != 1 || got[0].Existing {
				t.Fatalf("untagged dependency accepted: %+v", got)
			}
			hasMessage(t, got, "untagged specification (resolves to @main)", false)

			// consumer sorts before producer: policy must see all proposals,
			// not just dependencies installed earlier in the load loop.
			r.write("producer/.new-tag", "v1.0.0\n"+recorded+"\n")
			assertClean(t, r.check("HEAD"))
		})
	}
}

func TestReleaseAllowsSelfLatest(t *testing.T) {
	r := newRepo(t)
	r.write("consumer.md", "# Consumer\n\n[bare](https://c2sp.org/consumer#consumer)\n"+
		"[latest](https://c2sp.org/consumer@latest#consumer)\n")
	recorded := r.commit()
	r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
	r.commit()
	assertClean(t, r.check("HEAD"))
}
