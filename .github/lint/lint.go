package main

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"c2sp.org/C2SP/website/spec"
)

func main() {
	specs, err := filepath.Glob("../../*.md")
	if err != nil {
		panic(err)
	}
	for i := range specs {
		specs[i] = filepath.Base(specs[i])
		specs[i] = strings.TrimSuffix(specs[i], ".md")
	}
	sort.Slice(specs, func(i, j int) bool {
		return strings.ToLower(specs[i]) < strings.ToLower(specs[j])
	})

	readme, err := os.ReadFile("../README.md")
	if err != nil {
		panic(err)
	}

	for _, s := range specs {
		if !spec.ValidName(s) {
			log.Fatalf("invalid spec name %q", s)
		}
		if !strings.Contains(string(readme), "(https://c2sp.org/"+s+")") {
			log.Fatal("README.md does not contain " + s)
		}
	}
}
