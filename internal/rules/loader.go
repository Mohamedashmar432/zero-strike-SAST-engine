package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
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
	Tier          string    `yaml:"tier"`
	OncePerFile   bool      `yaml:"once_per_file"`
	SkipContexts  []string  `yaml:"skip_contexts"`
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
	NamePattern  string `yaml:"name_pattern"`
	ValuePattern string `yaml:"value_pattern"`
	ValueTainted bool   `yaml:"value_tainted"`
}

type argTextYAML struct {
	Index   int    `yaml:"index"`
	Pattern string `yaml:"pattern"`
}

type argKindYAML struct {
	Index int      `yaml:"index"`
	Kinds []string `yaml:"kinds"`
}

type filterYAML struct {
	Not                            *matchYAML   `yaml:"not"`
	ArgumentCount                  *int         `yaml:"argument_count"`
	HasAttribute                   string       `yaml:"has_attribute"`
	TaintedArgument                bool         `yaml:"tainted_argument"`
	TaintedArgumentIndex           *int         `yaml:"tainted_argument_index"`
	TaintedArgumentMinIndex        *int         `yaml:"tainted_argument_min_index"`
	TaintedRHS                     bool         `yaml:"tainted_rhs"`
	Kwarg                          *kwargYAML   `yaml:"kwarg"`
	ArgumentIdentifierMatches      string       `yaml:"argument_identifier_matches"`
	ArgumentLiteralMatches         string       `yaml:"argument_literal_matches"`
	RequireRealSource              bool         `yaml:"require_real_source"`
	ArgumentKindNotAt              *argKindYAML `yaml:"argument_kind_not_at"`
	HasBareExcept                  bool         `yaml:"has_bare_except"`
	CalleeMatches                  string       `yaml:"callee_matches"`
	DecoratorStackMatches          string       `yaml:"decorator_stack_matches"`
	EnclosingFunctionMatches       string       `yaml:"enclosing_function_matches"`
	ArgumentNotConstant            *int         `yaml:"argument_not_constant"`
	WrittenFileMatches             string       `yaml:"written_file_matches"`
	HasEmptyExceptHandler          bool         `yaml:"has_empty_except_handler"`
	LiteralArgument                *litArgYAML  `yaml:"literal_argument"`
	LHSFlowsToCall                 string       `yaml:"lhs_flows_to_call"`
	ExceptHandler                  *exceptYAML  `yaml:"except_handler"`
	TryBodyCallsOnly               string       `yaml:"try_body_calls_only"`
	ContextIdentifierMatches       string       `yaml:"context_identifier_matches"`
	EnclosingFunctionCalls         string       `yaml:"enclosing_function_calls"`
	EnclosingFunctionMentions      string       `yaml:"enclosing_function_mentions"`
	ArgumentLiteralIndex           *int         `yaml:"argument_literal_index"`
	AnyOf                          []filterYAML `yaml:"any_of"`
	CalleePattern                  string       `yaml:"callee_pattern"`
	CalleeCanonical                string       `yaml:"callee_canonical"`
	CalleeResolved                 bool         `yaml:"callee_resolved"`
	ArgumentMatchesAt              *argTextYAML `yaml:"argument_matches_at"`
	DynamicStringArgumentIndex     *int         `yaml:"dynamic_string_argument_index"`
	ArgumentReferencesErrorBinding bool         `yaml:"argument_references_error_binding"`
}

type litArgYAML struct {
	Index   int    `yaml:"index"`
	Pattern string `yaml:"pattern"`
}

type exceptYAML struct {
	Bare      *bool `yaml:"bare"`
	Empty     *bool `yaml:"empty"`
	Broad     *bool `yaml:"broad"`
	Commented *bool `yaml:"commented"`
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
		Tier:          core.Tier(ry.Tier),
		OncePerFile:   ry.OncePerFile,
		SkipContexts:  ry.SkipContexts,
		Match:         convertMatch(ry.Match),
	}

	if errs := l.validator.Validate(rule); len(errs) > 0 {
		return nil, fmt.Errorf("loader: parse %s: rule %s failed validation: %s", source, rule.ID, strings.Join(errs, "; "))
	}

	return []*Rule{rule}, nil
}

// convertMatch converts a matchYAML into a MatchPattern, recursing through any
// nested filters. Shared by the top-level match and each filter's `not`
// sub-pattern so that a `not` carries its full match shape (including its own
// filters), not just kind/callee/identifier/literal.
func convertMatch(m matchYAML) MatchPattern {
	return MatchPattern{
		Kind:          m.Kind,
		Callee:        m.Callee,
		CalleeSuffix:  m.CalleeSuffix,
		Identifier:    m.Identifier,
		Literal:       m.Literal,
		LHSIdentifier: m.LHSIdentifier,
		RHSLiteral:    m.RHSLiteral,
		Filters:       convertFilters(m.Filters),
	}
}

func convertFilters(fyamls []filterYAML) []Filter {
	if len(fyamls) == 0 {
		return nil
	}
	out := make([]Filter, 0, len(fyamls))
	for _, f := range fyamls {
		filter := Filter{
			ArgumentCount:                  f.ArgumentCount,
			HasAttribute:                   f.HasAttribute,
			TaintedArgument:                f.TaintedArgument,
			TaintedArgumentIndex:           f.TaintedArgumentIndex,
			TaintedArgumentMinIndex:        f.TaintedArgumentMinIndex,
			TaintedRHS:                     f.TaintedRHS,
			ArgumentIdentifierMatches:      f.ArgumentIdentifierMatches,
			ArgumentLiteralMatches:         f.ArgumentLiteralMatches,
			RequireRealSource:              f.RequireRealSource,
			ArgumentKindNotAt:              convertArgKind(f.ArgumentKindNotAt),
			HasBareExcept:                  f.HasBareExcept,
			HasEmptyExceptHandler:          f.HasEmptyExceptHandler,
			CalleeMatches:                  f.CalleeMatches,
			DecoratorStackMatches:          f.DecoratorStackMatches,
			EnclosingFunctionMatches:       f.EnclosingFunctionMatches,
			ArgumentNotConstant:            f.ArgumentNotConstant,
			WrittenFileMatches:             f.WrittenFileMatches,
			LHSFlowsToCall:                 f.LHSFlowsToCall,
			TryBodyCallsOnly:               f.TryBodyCallsOnly,
			ContextIdentifierMatches:       f.ContextIdentifierMatches,
			EnclosingFunctionCalls:         f.EnclosingFunctionCalls,
			EnclosingFunctionMentions:      f.EnclosingFunctionMentions,
			ArgumentLiteralIndex:           f.ArgumentLiteralIndex,
			CalleePattern:                  f.CalleePattern,
			CalleeCanonical:                f.CalleeCanonical,
			CalleeResolved:                 f.CalleeResolved,
			DynamicStringArgumentIndex:     f.DynamicStringArgumentIndex,
			ArgumentReferencesErrorBinding: f.ArgumentReferencesErrorBinding,
		}
		if f.LiteralArgument != nil {
			filter.LiteralArgument = &LiteralArgumentPattern{Index: f.LiteralArgument.Index, Pattern: f.LiteralArgument.Pattern}
		}
		if f.AnyOf != nil {
			// Keep an explicit "any_of: []" non-nil so the validator can
			// reject it; a nil AnyOf means the key was absent.
			filter.AnyOf = append([]Filter{}, convertFilters(f.AnyOf)...)
		}
		if f.ExceptHandler != nil {
			filter.ExceptHandler = &ExceptHandlerPattern{
				Bare:      f.ExceptHandler.Bare,
				Empty:     f.ExceptHandler.Empty,
				Broad:     f.ExceptHandler.Broad,
				Commented: f.ExceptHandler.Commented,
			}
		}
		if f.ArgumentMatchesAt != nil {
			filter.ArgumentMatchesAt = &ArgumentTextPattern{Index: f.ArgumentMatchesAt.Index, Pattern: f.ArgumentMatchesAt.Pattern}
		}
		if f.Kwarg != nil {
			filter.Kwarg = &KwargPattern{Name: f.Kwarg.Name, NamePattern: f.Kwarg.NamePattern, ValuePattern: f.Kwarg.ValuePattern, ValueTainted: f.Kwarg.ValueTainted}
		}
		if f.Not != nil {
			mp := convertMatch(*f.Not)
			filter.Not = &mp
		}
		out = append(out, filter)
	}
	return out
}

// convertArgKind maps the YAML form of argument_kind_not_at onto the rule
// struct. Returns nil for an absent key so the filter stays inactive.
func convertArgKind(y *argKindYAML) *ArgumentKindPattern {
	if y == nil {
		return nil
	}
	return &ArgumentKindPattern{Index: y.Index, Kinds: y.Kinds}
}
