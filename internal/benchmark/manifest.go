// Package benchmark scores ZeroStrike scan results against a labeled
// corpus (benchmark/corpus/), producing TP/FP/FN counts and precision/
// recall numbers instead of prose-based QA.
package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// DependencyExpectation matches an SCA finding by (package, ecosystem)
// rather than rule ID, since every SCA finding shares RuleID "ZS-SCA-001".
type DependencyExpectation struct {
	Package   string `yaml:"package"`
	Ecosystem string `yaml:"ecosystem"`
}

// Expectation is one "this file should produce a finding" declaration.
// Exactly one of RuleID or Dependency should be set.
type Expectation struct {
	RuleID     string                 `yaml:"rule_id,omitempty"`
	MinCount   int                    `yaml:"min_count,omitempty"`
	Dependency *DependencyExpectation `yaml:"dependency,omitempty"`
}

// Case is one labeled corpus file: what it is, and what it should (or, for
// a true negative, should not) trigger.
type Case struct {
	File      string        `yaml:"file"`
	Language  string        `yaml:"language,omitempty"`
	Ecosystem string        `yaml:"ecosystem,omitempty"`
	Expect    []Expectation `yaml:"expect"`
}

// Manifest is one corpus subdirectory's manifest.yaml.
type Manifest struct {
	Version string `yaml:"version"`
	Cases   []Case `yaml:"cases"`
}

// CorpusDir is one loaded corpus subdirectory (e.g. "python", "secrets").
type CorpusDir struct {
	Name     string // subdirectory name
	Dir      string // absolute path to the subdirectory (contains manifest.yaml + cases/)
	Manifest *Manifest
}

// LoadManifest loads and minimally validates one manifest.yaml.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, c := range m.Cases {
		if c.File == "" {
			return nil, fmt.Errorf("%s: case with empty file path", path)
		}
		for _, e := range c.Expect {
			if e.RuleID == "" && e.Dependency == nil {
				return nil, fmt.Errorf("%s: case %s has an expectation with neither rule_id nor dependency set", path, c.File)
			}
		}
	}
	return &m, nil
}

// LoadCorpus walks corpusRoot for immediate subdirectories containing a
// manifest.yaml, loading each as a CorpusDir. Subdirectories are visited in
// sorted order for deterministic report output.
func LoadCorpus(corpusRoot string) ([]CorpusDir, error) {
	entries, err := os.ReadDir(corpusRoot)
	if err != nil {
		return nil, fmt.Errorf("read corpus root %s: %w", corpusRoot, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var dirs []CorpusDir
	for _, name := range names {
		dir := filepath.Join(corpusRoot, name)
		manifestPath := filepath.Join(dir, "manifest.yaml")
		if _, statErr := os.Stat(manifestPath); statErr != nil {
			continue // not a corpus subdir (no manifest)
		}
		m, err := LoadManifest(manifestPath)
		if err != nil {
			return nil, err
		}
		dirs = append(dirs, CorpusDir{Name: name, Dir: dir, Manifest: m})
	}
	if len(dirs) == 0 {
		return nil, fmt.Errorf("no corpus subdirectories with manifest.yaml found under %s", corpusRoot)
	}
	return dirs, nil
}
