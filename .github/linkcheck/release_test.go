package linkcheck

import (
	"strings"
	"testing"
)

func TestReleaseChecksRecordedCommit(t *testing.T) {
	for _, version := range []string{"v1.0.0", "v0.1.0", "v1.0.0-rc.1"} {
		t.Run(version, func(t *testing.T) {
			r := newReleaseRepo(t)
			r.write("producer.md", "# Producer\n\n## Section\n")
			r.write("consumer.md", "# Consumer\n\n[dependency](https://c2sp.org/producer@main#section)\n")
			recorded := r.commit()
			// Fixing main does not fix the commit selected for publication.
			r.write("consumer.md", "# Consumer\n\nNo development link on main.\n")
			r.write("consumer/.new-tag", version+"\n"+recorded+"\n")
			r.commit()
			for _, base := range []string{"", "HEAD"} {
				got := r.check(base)
				if len(got) != 1 || got[0].Existing || got[0].File != "consumer.md" || got[0].Line != 3+specPreambleLines {
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
	r := newReleaseRepo(t)
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
			r := newReleaseRepo(t)
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
	r := newReleaseRepo(t)
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
	r := newReleaseRepo(t)
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

func TestReleaseAllowsImplicitMain(t *testing.T) {
	for _, version := range []string{"", "@latest"} {
		t.Run(version, func(t *testing.T) {
			r := newReleaseRepo(t)
			r.write("producer.md", "# Producer\n\n## Section\n")
			r.write("consumer.md", "# Consumer\n\n[dependency](https://c2sp.org/producer"+version+"#section)\n")
			recorded := r.commit()
			r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
			r.commit()
			assertClean(t, r.check("HEAD"))
			assertClean(t, r.check(""))

			// Releasing the dependency is also allowed, but not required.
			r.write("producer/.new-tag", "v1.0.0\n"+recorded+"\n")
			assertClean(t, r.check("HEAD"))
		})
	}
}

func TestReleaseAllowsSelfLatest(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("consumer.md", "# Consumer\n\n[bare](https://c2sp.org/consumer#consumer)\n"+
		"[latest](https://c2sp.org/consumer@latest#consumer)\n")
	recorded := r.commit()
	r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
	r.commit()
	assertClean(t, r.check("HEAD"))
}

func TestReleasePlaceholderMarkers(t *testing.T) {
	for _, marker := range []string{"TODO", "TK", "TBD", "FIXME"} {
		t.Run(marker, func(t *testing.T) {
			r := newReleaseRepo(t)
			r.write("consumer.md", "# Consumer\n\n"+marker+": finish this section.\n")
			recorded := r.commit()
			// Placeholders remain allowed during ordinary development.
			assertClean(t, r.check(""))
			r.write("consumer.md", "# Consumer\n\nNow complete on main.\n")
			r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
			r.commit()
			got := r.check("HEAD")
			if len(got) != 1 || got[0].Existing || got[0].Line != specPreambleLines+3 {
				t.Fatalf("placeholder in selected source not rejected: %+v", got)
			}
			hasMessage(t, got, "unfinished "+marker+" placeholder", false)
			hasMessage(t, got, recorded, false)
		})
	}
}

func TestPlaceholderWordBoundaries(t *testing.T) {
	for _, src := range []string{
		"TODO\n", "[TK]\n", "<!-- TBD -->\n", "```go\n// FIXME\n```\n", "`TODO`\n",
	} {
		if got := lintPlaceholders([]byte(src)); len(got) != 1 {
			t.Errorf("placeholder not found in %q: %+v", src, got)
		}
	}
	for _, src := range []string{
		"TODOs FIXMEs TKTK", "TODO_count some_TBD someTKthing", "éTODO TODO雪", "TODO\u0301",
		"todo tk tbd fixme", "- [ ] A deliberately unchecked item.\n",
	} {
		if got := lintPlaceholders([]byte(src)); len(got) != 0 {
			t.Errorf("non-placeholder flagged in %q: %+v", src, got)
		}
	}
}

func TestReleaseAllowsUncheckedTasksAndUnrelatedPlaceholders(t *testing.T) {
	r := newReleaseRepo(t)
	r.write("consumer.md", "# Consumer\n\n- [ ] A task-list item.\n")
	r.write("other.md", "# Other\n\nTODO: another spec is still in development.\n")
	recorded := r.commit()
	r.git("tag", "other/v1.0.0")
	// Only the proposed source is checked; current main may have new TODOs.
	r.write("consumer.md", "# Consumer\n\nFIXME: new work on main.\n")
	r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
	r.commit()
	assertClean(t, r.check(""))
	assertClean(t, r.check("HEAD"))
}

func TestReleaseRunsLatestSourceLinters(t *testing.T) {
	tests := []struct {
		name, source, want string
	}{
		{"math", testSpec("consumer", "# Consumer\n\n$\\frac{$\n"), "invalid mathematical expression"},
		{"front matter", "# Consumer\n\nNo front matter.\n", "missing front matter"},
		{"description", strings.Replace(testSpec("consumer", "# Consumer\n"), "Test spec", "Test spec.", 1), "description should not end with a period"},
		{"headings", testSpec("consumer", "# Consumer\n\n# Another title\n"), "2 top-level headings"},
		{"warning", strings.Replace(testSpec("consumer", "# Consumer\n"), "[!WARNING]", "[!NOTE]", 1), `expected "> [!WARNING]"`},
		{"GitHub link", testSpec("consumer", "# Consumer\n\n[spec](https://github.com/C2SP/C2SP/blob/main/producer.md)\n"), "link to GitHub instead of c2sp.org"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRepo(t) // Use the intentionally malformed source verbatim.
			r.write("consumer.md", tt.source)
			recorded := r.commit()
			r.write("consumer.md", testSpec("consumer", "# Consumer\n\nFixed on main.\n"))
			r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
			r.commit()
			got := r.check("HEAD")
			hasMessage(t, got, tt.want, false)
			hasMessage(t, got, "commit "+recorded, false)
		})
	}
}

func TestReleaseSourceLintersIgnoreOtherSpecsAtCommit(t *testing.T) {
	r := newRepo(t)
	r.write("consumer.md", testSpec("consumer", "# Consumer\n"))
	r.write("other.md", "# Other\n\n$\\frac{$\n\nTODO\n")
	recorded := r.commit()
	// The current files and the other historical file must not be substituted
	// for consumer.md at recorded, which is valid.
	r.write("other.md", testSpec("other", "# Other\n"))
	r.write("consumer.md", testSpec("consumer", "# Consumer\n\n$\\frac{$\n\nTODO\n"))
	r.write("consumer/.new-tag", "v1.0.0\n"+recorded+"\n")
	r.commit()
	assertClean(t, r.check("HEAD"))
}
