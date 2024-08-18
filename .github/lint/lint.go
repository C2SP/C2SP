package main

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

	for _, spec := range specs {
		if !strings.Contains(string(readme), "(https://c2sp.org/"+spec+")") {
			log.Fatal("README.md does not contain " + spec)
		}
	}
}
