package fwdetect

import (
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

//go:embed profiles/*.yaml
var profilesFS embed.FS

// Profile is one framework's detection evidence, request sources and
// entry-point shapes, loaded from profiles/<name>.yaml.
type Profile struct {
	Name      string
	Languages []core.Language

	fileEvidence []fileEvidence
	manifests    []manifestEvidence
	// Sources are the request accessors that introduce taint in a file with
	// this framework detected (high confidence).
	Sources []*regexp.Regexp
	cond    []condSources
	entries []entryPoint
	params  paramPolicy
	// boundAttrs marks a parameter request-bound wherever it appears.
	boundAttrs *regexp.Regexp
}

type fileEvidence struct {
	label string
	re    *regexp.Regexp
}

type manifestEvidence struct {
	file     *regexp.Regexp // against the manifest's slash-separated path
	contains *regexp.Regexp // against its content
	label    string
}

type condSources struct {
	when     *regexp.Regexp // against the file's evidence labels
	patterns []*regexp.Regexp
}

// entryPoint is one shape of function the framework invokes with
// request-derived data. A function matches when it satisfies the class shape
// (a method of a matching class) or the registration shape (passed to a
// matching call).
type entryPoint struct {
	classBases, classAttrs    *regexp.Regexp
	methodNames               *regexp.Regexp
	excludeMethodAttrs        *regexp.Regexp
	publicOnly, defaultPublic bool
	callee                    *regexp.Regexp
	pathArg                   bool
	// methodAttrs matches the names of the annotations or decorators on the
	// function itself (@GetMapping, @app.route, @Get). With no class shape it
	// stands alone (a decorated function anywhere); with one, both must match.
	methodAttrs *regexp.Regexp
	// functionNames matches the function's own name (Next.js GET, handler).
	functionNames *regexp.Regexp
	// firstParam matches the name of the function's first parameter (a Django
	// view takes request first).
	firstParam *regexp.Regexp
	// whenEvidence restricts the shape to files whose evidence labels match;
	// freeFunctions makes every non-nested function of the file match
	// ("use server" files: each exported function is a server action).
	whenEvidence  *regexp.Regexp
	freeFunctions bool
}

type paramPolicy struct {
	mode         string // all | first | typed | none
	types        []*regexp.Regexp
	excludeTypes *regexp.Regexp
	excludeAttrs *regexp.Regexp
	excludeNames *regexp.Regexp
	weak         bool
}

type profileYAML struct {
	Name         string   `yaml:"name"`
	Languages    []string `yaml:"languages"`
	FileEvidence []struct {
		Label   string `yaml:"label"`
		Pattern string `yaml:"pattern"`
	} `yaml:"file_evidence"`
	Manifests []struct {
		File     string `yaml:"file"`
		Contains string `yaml:"contains"`
		Label    string `yaml:"label"`
	} `yaml:"manifests"`
	Sources            []string `yaml:"sources"`
	ConditionalSources []struct {
		WhenEvidence string   `yaml:"when_evidence"`
		Patterns     []string `yaml:"patterns"`
	} `yaml:"conditional_sources"`
	EntryPoints []struct {
		ClassBases         string `yaml:"class_bases"`
		ClassAttrs         string `yaml:"class_attrs"`
		MethodNames        string `yaml:"method_names"`
		ExcludeMethodAttrs string `yaml:"exclude_method_attrs"`
		PublicOnly         bool   `yaml:"public_only"`
		DefaultPublic      bool   `yaml:"default_public"`
		Callee             string `yaml:"callee"`
		PathArg            bool   `yaml:"path_arg"`
		MethodAttrs        string `yaml:"method_attrs"`
		FunctionNames      string `yaml:"function_names"`
		FirstParam         string `yaml:"first_param"`
		WhenEvidence       string `yaml:"when_evidence"`
		FreeFunctions      bool   `yaml:"free_functions"`
	} `yaml:"entry_points"`
	Params struct {
		Mode         string   `yaml:"mode"`
		Types        []string `yaml:"types"`
		ExcludeTypes string   `yaml:"exclude_types"`
		ExcludeAttrs string   `yaml:"exclude_attrs"`
		ExcludeNames string   `yaml:"exclude_names"`
		Weak         bool     `yaml:"weak"`
	} `yaml:"params"`
	BoundParamAttrs string `yaml:"bound_param_attrs"`
}

var (
	loadOnce sync.Once
	profiles map[string]*Profile
	loadErr  error
)

// Profiles returns every embedded profile by name. A malformed profile is a
// build defect, so it panics at first use rather than silently disabling the
// framework (profiles_test.go loads them all).
func Profiles() map[string]*Profile {
	loadOnce.Do(func() { profiles, loadErr = loadProfiles() })
	if loadErr != nil {
		panic(loadErr)
	}
	return profiles
}

// ProfileFor returns the named profile, or nil.
func ProfileFor(name string) *Profile { return Profiles()[name] }

// Names lists the known framework names, sorted. The rule validator accepts
// exactly these in a rule's frameworks list.
func Names() []string {
	var out []string
	for n := range Profiles() {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func loadProfiles() (map[string]*Profile, error) {
	files, err := profilesFS.ReadDir("profiles")
	if err != nil {
		return nil, err
	}
	out := make(map[string]*Profile, len(files))
	for _, f := range files {
		data, err := profilesFS.ReadFile("profiles/" + f.Name())
		if err != nil {
			return nil, err
		}
		p, err := parseProfile(data)
		if err != nil {
			return nil, fmt.Errorf("fwdetect: profile %s: %w", f.Name(), err)
		}
		out[p.Name] = p
	}
	return out, nil
}

// rx compiles an optional pattern; empty means no constraint (nil).
func rx(pat string) (*regexp.Regexp, error) {
	if pat == "" {
		return nil, nil
	}
	return regexp.Compile(pat)
}

func rxAll(pats []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, s := range pats {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

func parseProfile(data []byte) (*Profile, error) {
	var y profileYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return nil, err
	}
	if y.Name == "" {
		return nil, fmt.Errorf("missing name")
	}
	p := &Profile{Name: y.Name}
	for _, l := range y.Languages {
		p.Languages = append(p.Languages, core.Language(l))
	}
	var err error
	for _, e := range y.FileEvidence {
		re, err := regexp.Compile(e.Pattern)
		if err != nil {
			return nil, err
		}
		p.fileEvidence = append(p.fileEvidence, fileEvidence{e.Label, re})
	}
	for _, m := range y.Manifests {
		f, err := regexp.Compile(m.File)
		if err != nil {
			return nil, err
		}
		c, err := regexp.Compile(m.Contains)
		if err != nil {
			return nil, err
		}
		p.manifests = append(p.manifests, manifestEvidence{f, c, m.Label})
	}
	if p.Sources, err = rxAll(y.Sources); err != nil {
		return nil, err
	}
	for _, c := range y.ConditionalSources {
		w, err := regexp.Compile(c.WhenEvidence)
		if err != nil {
			return nil, err
		}
		pats, err := rxAll(c.Patterns)
		if err != nil {
			return nil, err
		}
		p.cond = append(p.cond, condSources{w, pats})
	}
	for _, e := range y.EntryPoints {
		ep := entryPoint{publicOnly: e.PublicOnly, defaultPublic: e.DefaultPublic, pathArg: e.PathArg, freeFunctions: e.FreeFunctions}
		for dst, pat := range map[**regexp.Regexp]string{
			&ep.classBases: e.ClassBases, &ep.classAttrs: e.ClassAttrs, &ep.methodNames: e.MethodNames,
			&ep.excludeMethodAttrs: e.ExcludeMethodAttrs, &ep.callee: e.Callee,
			&ep.methodAttrs: e.MethodAttrs, &ep.functionNames: e.FunctionNames,
			&ep.firstParam: e.FirstParam, &ep.whenEvidence: e.WhenEvidence,
		} {
			if *dst, err = rx(pat); err != nil {
				return nil, err
			}
		}
		p.entries = append(p.entries, ep)
	}
	p.params.weak = y.Params.Weak
	p.params.mode = y.Params.Mode
	if p.params.mode == "" {
		p.params.mode = "none"
	}
	if p.params.types, err = rxAll(y.Params.Types); err != nil {
		return nil, err
	}
	if p.params.excludeTypes, err = rx(y.Params.ExcludeTypes); err != nil {
		return nil, err
	}
	if p.params.excludeAttrs, err = rx(y.Params.ExcludeAttrs); err != nil {
		return nil, err
	}
	if p.params.excludeNames, err = rx(y.Params.ExcludeNames); err != nil {
		return nil, err
	}
	if p.boundAttrs, err = rx(y.BoundParamAttrs); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Profile) appliesTo(lang core.Language) bool {
	for _, l := range p.Languages {
		if l == lang {
			return true
		}
	}
	return false
}

// SourcesFor returns the request-source patterns active for a file whose
// detection produced the given evidence labels: the profile's own, plus any
// conditional group whose condition one of the labels satisfies.
func (p *Profile) SourcesFor(evidence []string) []*regexp.Regexp {
	out := append([]*regexp.Regexp(nil), p.Sources...)
	for _, c := range p.cond {
		for _, ev := range evidence {
			if c.when.MatchString(ev) {
				out = append(out, c.patterns...)
				break
			}
		}
	}
	return out
}

// Entries answers, for one file's IR, which parameters of which functions the
// framework binds from the request.
type Entries struct {
	p        *Profile
	evidence []string // the file's evidence labels, for when_evidence shapes
	// registered holds names of functions passed by reference to a
	// registration call (fastify.get('/x', handler)), per entry point index.
	registered map[string]int
}

// Index scans root once for registration calls that pass a function by name,
// so a later Params lookup is a map read.
func (p *Profile) Index(root *ir.IRNode) *Entries { return p.IndexWith(root, nil) }

// IndexWith is Index for a file whose detection produced the given evidence
// labels (entry-point shapes with when_evidence consult them).
func (p *Profile) IndexWith(root *ir.IRNode, evidence []string) *Entries {
	e := &Entries{p: p, evidence: evidence, registered: map[string]int{}}
	ir.Walk(root, func(n *ir.IRNode) bool {
		if n.Kind != ir.NodeKindCall {
			return true
		}
		i := p.registrationIndex(n)
		if i < 0 || len(n.Children) < 2 {
			return true
		}
		for _, arg := range n.Children[1:] {
			e.collectNames(arg, 0, i)
		}
		return true
	})
	return e
}

// collectNames records identifier arguments up to two levels below a call's
// argument container (JS: arguments > identifier; C#: argument_list > argument
// > identifier).
func (e *Entries) collectNames(n *ir.IRNode, depth, entry int) {
	if n.Kind == ir.NodeKindIdentifier && n.Text != "" && depth > 0 {
		e.registered[n.Text] = entry
		return
	}
	if depth >= 2 || n.Kind == ir.NodeKindFunction {
		return
	}
	for _, c := range n.Children {
		e.collectNames(c, depth+1, entry)
	}
}

// registrationIndex returns the index of the entry point whose callee shape
// call matches, or -1.
func (p *Profile) registrationIndex(call *ir.IRNode) int {
	src, _ := call.Attrs["callee_src"].(string)
	if src == "" {
		return -1
	}
	for i, ep := range p.entries {
		if ep.callee == nil || !ep.callee.MatchString(src) {
			continue
		}
		if ep.pathArg && !hasPathLiteral(call) {
			continue
		}
		return i
	}
	return -1
}

// hasPathLiteral reports whether a call's first literal argument looks like a
// route path ("/users/:id", "*"): it keeps cache.get(key) and axios.get(url,
// cb) from being read as route registrations.
func hasPathLiteral(call *ir.IRNode) bool {
	for _, arg := range call.Children[1:] {
		var lit *ir.IRNode
		ir.Walk(arg, func(n *ir.IRNode) bool {
			if lit == nil && n.Kind == ir.NodeKindLiteral {
				lit = n
			}
			return lit == nil
		})
		if lit != nil {
			return strings.HasPrefix(lit.Text, "/") || lit.Text == "*"
		}
	}
	return false
}

// Params returns the names of fn's parameters the framework binds from the
// request: the entry-point parameters selected by the profile's policy, plus
// any parameter carrying a bound attribute ([FromQuery]) wherever fn sits.
func (e *Entries) Params(fn *ir.IRNode) []string {
	strong, weak := e.ParamsSplit(fn)
	return append(strong, weak...)
}

// ParamsSplit is Params split by how sure the binding is. A parameter carrying
// a bound attribute ([FromQuery], @RequestParam) is strong. One selected only
// by the entry-point policy is strong too, unless the profile marks its policy
// weak (params.weak): a route variable or an unannotated argument of a view is
// request data only by position, so the taint pass seeds it the way it seeds
// every parameter when no framework is known.
func (e *Entries) ParamsSplit(fn *ir.IRNode) (strong, weak []string) {
	params, _ := fn.Attrs["parameters"].([]string)
	if len(params) == 0 {
		return nil, nil
	}
	types, _ := fn.Attrs["param_types"].([]string)
	attrs, _ := fn.Attrs["param_attrs"].([]string)
	seen := map[string]bool{}
	add := func(i int, isWeak bool) {
		if seen[params[i]] {
			return
		}
		seen[params[i]] = true
		if isWeak {
			weak = append(weak, params[i])
		} else {
			strong = append(strong, params[i])
		}
	}
	if e.p.boundAttrs != nil {
		for i := range params {
			if i < len(attrs) && attrListMatches(e.p.boundAttrs, attrs[i]) {
				add(i, false)
			}
		}
	}
	if e.isEntry(fn) {
		for i := range params {
			if e.p.policyBinds(params, i, types, attrs) {
				add(i, e.p.params.weak)
			}
		}
	}
	return strong, weak
}

// policyBinds applies the profile's parameter policy to parameter i.
func (p *Profile) policyBinds(params []string, i int, types, attrs []string) bool {
	typ, attr := "", ""
	if i < len(types) {
		typ = types[i]
	}
	if i < len(attrs) {
		attr = attrs[i]
	}
	pp := p.params
	if pp.excludeNames != nil && pp.excludeNames.MatchString(params[i]) {
		return false
	}
	if pp.excludeAttrs != nil && attrListMatches(pp.excludeAttrs, attr) {
		return false
	}
	if pp.excludeTypes != nil && typ != "" && pp.excludeTypes.MatchString(typ) {
		return false
	}
	switch pp.mode {
	case "all":
		return true
	case "first":
		return i == 0
	case "typed":
		for _, re := range pp.types {
			if re.MatchString(typ) {
				return true
			}
		}
	}
	return false
}

func attrListMatches(re *regexp.Regexp, joined string) bool {
	if joined == "" {
		return false
	}
	for _, a := range strings.Split(joined, ",") {
		if re.MatchString(a) {
			return true
		}
	}
	return false
}

// isEntry reports whether fn matches any of the profile's entry-point shapes.
func (e *Entries) isEntry(fn *ir.IRNode) bool {
	class := ownerClass(fn)
	for i, ep := range e.p.entries {
		if ep.callee != nil {
			if e.registeredAs(fn, i) {
				return true
			}
			continue
		}
		if ep.matchesFunction(fn, e.evidence) {
			return true
		}
		if ep.methodAttrs != nil && ep.classBases == nil && ep.classAttrs == nil {
			if ep.methodAttrsMatch(fn) {
				return true
			}
			continue
		}
		if class != nil && ep.matchesMethod(fn, class) {
			return true
		}
	}
	return false
}

// matchesFunction applies the class-independent shapes: a function by name, by
// first parameter, or any top-level function of a file with given evidence.
func (ep entryPoint) matchesFunction(fn *ir.IRNode, evidence []string) bool {
	if ep.functionNames == nil && ep.firstParam == nil && !ep.freeFunctions {
		return false
	}
	if ep.whenEvidence != nil {
		ok := false
		for _, ev := range evidence {
			if ep.whenEvidence.MatchString(ev) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if ep.functionNames != nil && !ep.functionNames.MatchString(functionRefName(fn)) {
		return false
	}
	if ep.firstParam != nil {
		params, _ := fn.Attrs["parameters"].([]string)
		if len(params) == 0 || !ep.firstParam.MatchString(params[0]) {
			return false
		}
	}
	if ep.freeFunctions {
		for p := fn.Parent; p != nil; p = p.Parent {
			if p.Kind == ir.NodeKindFunction || p.Kind == ir.NodeKindClass {
				return false
			}
		}
	}
	return true
}

// methodAttrsMatch reports whether any annotation or decorator on fn matches.
func (ep entryPoint) methodAttrsMatch(fn *ir.IRNode) bool {
	for _, key := range []string{"attributes", "decorators"} {
		list, _ := fn.Attrs[key].([]string)
		for _, a := range list {
			if ep.methodAttrs.MatchString(a) {
				return true
			}
		}
	}
	return false
}

// matchesMethod applies a class-shaped entry point to a method of class.
func (ep entryPoint) matchesMethod(fn, class *ir.IRNode) bool {
	if ep.classBases == nil && ep.classAttrs == nil {
		return false
	}
	name := methodName(fn)
	if ctor, _ := class.Attrs["class_name"].(string); name != "" && name == ctor {
		return false // constructor: its parameters are injected services
	}
	if _, isMethod := fn.Attrs["modifiers"]; !isMethod && fn.Attrs["function_name"] == nil {
		return false
	}
	if !(ep.classMatches(class)) {
		return false
	}
	if ep.publicOnly && !isPublic(fn, ep.defaultPublic) {
		return false
	}
	if ep.methodNames != nil && !ep.methodNames.MatchString(name) {
		return false
	}
	if ep.methodAttrs != nil && !ep.methodAttrsMatch(fn) {
		return false
	}
	if ep.excludeMethodAttrs != nil {
		attrs, _ := fn.Attrs["attributes"].([]string)
		for _, a := range attrs {
			if ep.excludeMethodAttrs.MatchString(a) {
				return false
			}
		}
	}
	return true
}

func (ep entryPoint) classMatches(class *ir.IRNode) bool {
	if ep.classBases != nil {
		bases, _ := class.Attrs["bases"].([]string)
		for _, b := range bases {
			if ep.classBases.MatchString(stripGenerics(b)) {
				return true
			}
		}
	}
	if ep.classAttrs != nil {
		attrs, _ := class.Attrs["attributes"].([]string)
		for _, a := range attrs {
			if ep.classAttrs.MatchString(a) {
				return true
			}
		}
	}
	return false
}

func stripGenerics(s string) string {
	if i := strings.IndexByte(s, '<'); i >= 0 {
		return s[:i]
	}
	return s
}

func methodName(fn *ir.IRNode) string {
	if v, _ := fn.Attrs["function_name"].(string); v != "" {
		return v
	}
	return ""
}

func isPublic(fn *ir.IRNode, defaultPublic bool) bool {
	mods, _ := fn.Attrs["modifiers"].([]string)
	if defaultPublic {
		for _, m := range mods {
			if m == "private" || m == "protected" {
				return false
			}
		}
		return true
	}
	for _, m := range mods {
		if m == "public" {
			return true
		}
	}
	return false
}

// ownerClass returns the class declaration fn is a direct member of, or nil
// for a free or nested function.
func ownerClass(fn *ir.IRNode) *ir.IRNode {
	for p := fn.Parent; p != nil; p = p.Parent {
		switch p.Kind {
		case ir.NodeKindClass:
			return p
		case ir.NodeKindFunction:
			return nil
		}
	}
	return nil
}

// registeredAs reports whether fn is the handler of a registration call that
// matches entry point i: passed inline (directly, or inside an options
// object) or by name.
func (e *Entries) registeredAs(fn *ir.IRNode, i int) bool {
	if idx, ok := e.registered[functionRefName(fn)]; ok && idx == i && functionRefName(fn) != "" {
		return true
	}
	// Climb through argument containers and option objects to the call.
	for p := fn.Parent; p != nil; p = p.Parent {
		switch p.Kind {
		case ir.NodeKindCall:
			return e.p.registrationIndex(p) == i
		case ir.NodeKindFunction, ir.NodeKindClass, ir.NodeKindModule, ir.NodeKindBlock,
			ir.NodeKindAssignment, ir.NodeKindReturn:
			return false
		}
	}
	return false
}

// functionRefName is the name a function can be referenced by: its declared
// name, a method name, or the variable it is assigned to.
func functionRefName(fn *ir.IRNode) string {
	if v, _ := fn.Attrs["function_name"].(string); v != "" {
		return v
	}
	if v, _ := fn.Attrs["method_name"].(string); v != "" {
		return v
	}
	if fn.Parent != nil && fn.Parent.Kind == ir.NodeKindAssignment {
		if lhs, _ := fn.Parent.Attrs["lhs"].(string); lhs != "" {
			return lhs
		}
	}
	// function handler(req, reply) {}: the name is the first identifier child.
	for _, c := range fn.Children {
		if c.Kind == ir.NodeKindIdentifier && c.Text != "" {
			return c.Text
		}
	}
	return ""
}
