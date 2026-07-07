package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/zerostrike/scanner/internal/core"
)

// ruleYAML is the wire format that maps YAML fields to Rule fields.
type ruleYAML struct {
	ID            string    `yaml:"id"`
	Name          string    `yaml:"name"`
	Version       string    `yaml:"version"`
	Language      string    `yaml:"language"`
	Category      string    `yaml:"category"`
	Severity      string    `yaml:"severity"`
	Confidence    string    `yaml:"confidence"`
	Description   string    `yaml:"description"`
	Message       string    `yaml:"message"`
	Tags          []string  `yaml:"tags"`
	CWE           []string  `yaml:"cwe"`
	OWASP         []string  `yaml:"owasp"`
	References    []string  `yaml:"references"`
	Match         matchYAML `yaml:"match"`
	FixSuggestion string    `yaml:"fix_suggestion"`
	Rationale     string    `yaml:"rationale"`
	Lifecycle     string    `yaml:"lifecycle"`
}

type matchYAML struct {
	Kind          string       `yaml:"kind"`
	Callee        string       `yaml:"callee"`
	CalleeSuffix  bool         `yaml:"callee_suffix"`
	Identifier    string       `yaml:"identifier"`
	Literal       string       `yaml:"literal"`
	LHSIdentifier string       `yaml:"lhs_identifier"`
	RHSLiteral    string       `yaml:"rhs_literal"`
	Filters       []filterYAML `yaml:"filters"`
}

type kwargYAML struct {
	Name         string `yaml:"name"`
	ValuePattern string `yaml:"value_pattern"`
}

type filterYAML struct {
	Not                       *matchYAML `yaml:"not"`
	ArgumentCount             *int       `yaml:"argument_count"`
	HasAttribute              string     `yaml:"has_attribute"`
	TaintedArgument           bool       `yaml:"tainted_argument"`
	TaintedRHS                bool       `yaml:"tainted_rhs"`
	Kwarg                     *kwargYAML `yaml:"kwarg"`
	ArgumentIdentifierMatches string     `yaml:"argument_identifier_matches"`
	HasBareExcept             bool       `yaml:"has_bare_except"`
	HasEmptyExceptHandler     bool       `yaml:"has_empty_except_handler"`
}

type defaultLoader struct {
	fsys      fs.FS     // nil = OS filesystem
	validator Validator // shared validator instance (stateless, reused for all rules)
}

// NewLoader returns a Loader. Pass an fs.FS to read from it (e.g. EmbeddedFS);
// omit to read from the OS filesystem.
func NewLoader(fsys ...fs.FS) Loader {
	if len(fsys) > 0 && fsys[0] != nil {
		return &defaultLoader{fsys: fsys[0], validator: NewValidator()}
	}
	return &defaultLoader{validator: NewValidator()}
}

// Load parses a single YAML rule file and returns it as a one-element slice.
func (l *defaultLoader) Load(source string) ([]*Rule, error) {
	data, err := l.readFile(source)
	if err != nil {
		return nil, fmt.Errorf("loader: read %s: %w", source, err)
	}
	return l.parseYAML(source, data)
}

// LoadDir loads all *.yaml files from the given directory.
func (l *defaultLoader) LoadDir(dir string) ([]*Rule, error) {
	fsys, readDir := l.fsys, dir
	if fsys == nil {
		fsys = os.DirFS(dir)
		readDir = "."
	}

	entries, err := fs.ReadDir(fsys, readDir)
	if err != nil {
		return nil, fmt.Errorf("loader: readdir %s: %w", dir, err)
	}

	var all []*Rule
	var errs []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		filePath := path.Join(readDir, e.Name())
		data, err := fs.ReadFile(fsys, filePath)
		if err != nil {
			return nil, fmt.Errorf("loader: read %s: %w", filePath, err)
		}
		rules, err := l.parseYAML(filePath, data)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		all = append(all, rules...)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("loader: readdir %s: %d rule(s) failed validation:\n%s", dir, len(errs), strings.Join(errs, "\n"))
	}
	return all, nil
}

func (l *defaultLoader) readFile(source string) ([]byte, error) {
	if l.fsys != nil {
		return fs.ReadFile(l.fsys, source)
	}
	return os.ReadFile(source)
}

func (l *defaultLoader) parseYAML(source string, data []byte) ([]*Rule, error) {
	var ry ruleYAML
	if err := yaml.Unmarshal(data, &ry); err != nil {
		return nil, fmt.Errorf("loader: parse %s: %w", source, err)
	}
	rule := &Rule{
		ID:            ry.ID,
		Name:          ry.Name,
		Version:       ry.Version,
		Language:      core.Language(ry.Language),
		Category:      ry.Category,
		Severity:      core.Severity(ry.Severity),
		Confidence:    core.Confidence(ry.Confidence),
		Description:   ry.Description,
		Message:       ry.Message,
		Tags:          ry.Tags,
		CWE:           ry.CWE,
		OWASP:         ry.OWASP,
		References:    ry.References,
		FixSuggestion: ry.FixSuggestion,
		Rationale:     ry.Rationale,
		Lifecycle:     ry.Lifecycle,
		Match: MatchPattern{
			Kind:          ry.Match.Kind,
			Callee:        ry.Match.Callee,
			CalleeSuffix:  ry.Match.CalleeSuffix,
			Identifier:    ry.Match.Identifier,
			Literal:       ry.Match.Literal,
			LHSIdentifier: ry.Match.LHSIdentifier,
			RHSLiteral:    ry.Match.RHSLiteral,
			Filters:       convertFilters(ry.Match.Filters),
		},
	}

	if errs := l.validator.Validate(rule); len(errs) > 0 {
		return nil, fmt.Errorf("loader: parse %s: rule %s failed validation: %s", source, rule.ID, strings.Join(errs, "; "))
	}

	return []*Rule{rule}, nil
}

func convertFilters(fyamls []filterYAML) []Filter {
	if len(fyamls) == 0 {
		return nil
	}
	out := make([]Filter, 0, len(fyamls))
	for _, f := range fyamls {
		filter := Filter{
			ArgumentCount:             f.ArgumentCount,
			HasAttribute:              f.HasAttribute,
			TaintedArgument:           f.TaintedArgument,
			TaintedRHS:                f.TaintedRHS,
			ArgumentIdentifierMatches: f.ArgumentIdentifierMatches,
			HasBareExcept:             f.HasBareExcept,
			HasEmptyExceptHandler:     f.HasEmptyExceptHandler,
		}
		if f.Kwarg != nil {
			filter.Kwarg = &KwargPattern{Name: f.Kwarg.Name, ValuePattern: f.Kwarg.ValuePattern}
		}
		if f.Not != nil {
			mp := MatchPattern{
				Kind:       f.Not.Kind,
				Callee:     f.Not.Callee,
				Identifier: f.Not.Identifier,
				Literal:    f.Not.Literal,
			}
			filter.Not = &mp
		}
		out = append(out, filter)
	}
	return out
}
