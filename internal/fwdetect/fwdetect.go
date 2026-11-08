// Package fwdetect decides, per source file, which web framework the code
// targets and with what confidence, and holds each framework's profile: the
// request accessors that count as taint sources and the shapes of the
// functions the framework calls with request data.
//
// Evidence, strongest first: file evidence (an import, a base class, an
// attribute, a registration call) gives "high"; a manifest in the file's
// directory or any ancestor (.csproj, package.json, composer.json) gives
// "medium". Only a high detection changes how the taint pass seeds a file (see
// internal/analyzer/taint.BuildContext), so seeding depends on the file's own
// bytes and stays valid under the per-file finding cache.
package fwdetect

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// Confidence levels of a detection.
const (
	High   = "high"   // file-level evidence
	Medium = "medium" // manifest evidence only
)

// Detected is one framework found for one file.
type Detected struct {
	Framework  string
	Confidence string
	Evidence   []string
}

// Summary aggregates detections over a scan: how many files each framework was
// detected in at each confidence.
type Summary struct {
	Framework  string
	Confidence string
	Files      int
}

// manifestHit is a framework a manifest vouches for, scoped to its directory.
type manifestHit struct {
	framework string
	label     string
}

// Detector holds the scan-wide manifest evidence. It is built once per scan
// and is safe for concurrent Detect calls.
type Detector struct {
	byDir map[string][]manifestHit // slash-separated directory -> hits

	mu    sync.Mutex
	files map[string]map[string]bool // framework|confidence -> set of paths
}

// New reads every manifest in files (paths as the walker produced them) once.
// A file that cannot be read contributes no evidence.
func New(files []string) *Detector {
	d := &Detector{byDir: map[string][]manifestHit{}, files: map[string]map[string]bool{}}
	for _, f := range files {
		slash := filepath.ToSlash(f)
		base := slash[strings.LastIndexByte(slash, '/')+1:]
		if !isManifestName(base) {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		dir := dirOf(slash)
		for _, p := range sortedProfiles() {
			for _, m := range p.manifests {
				if m.file.MatchString(slash) && m.contains.Match(data) {
					d.byDir[dir] = append(d.byDir[dir], manifestHit{p.Name, m.label})
				}
			}
		}
	}
	return d
}

func isManifestName(base string) bool {
	switch {
	case base == "package.json", base == "composer.json", base == "packages.config",
		base == "pom.xml", base == "build.gradle", base == "build.gradle.kts",
		base == "pyproject.toml", base == "Pipfile", base == "go.mod":
		return true
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return true
	case strings.HasSuffix(base, ".csproj"):
		return true
	}
	return false
}

func dirOf(slash string) string {
	if i := strings.LastIndexByte(slash, '/'); i >= 0 {
		return slash[:i]
	}
	return "."
}

var (
	sortedOnce sync.Once
	sorted     []*Profile
)

// sortedProfiles returns the profiles in name order so detection output is
// deterministic.
func sortedProfiles() []*Profile {
	sortedOnce.Do(func() {
		for _, p := range Profiles() {
			sorted = append(sorted, p)
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	})
	return sorted
}

// Detect returns the frameworks detected for the file at path with the given
// language and source, sorted by framework name. A framework with file
// evidence is "high" (the manifest label, if any, is appended to its evidence);
// one that only a manifest above the file vouches for is "medium". The result
// is also recorded for Summaries.
func (d *Detector) Detect(path string, lang core.Language, src []byte) []Detected {
	slash := filepath.ToSlash(path)
	var out []Detected
	for _, p := range sortedProfiles() {
		if !p.appliesTo(lang) {
			continue
		}
		var ev []string
		for _, fe := range p.fileEvidence {
			if fe.re.Match(src) {
				ev = append(ev, fe.label)
			}
		}
		manifest := d.manifestEvidence(slash, p.Name)
		switch {
		case len(ev) > 0:
			out = append(out, Detected{p.Name, High, append(ev, manifest...)})
		case len(manifest) > 0:
			out = append(out, Detected{p.Name, Medium, manifest})
		}
	}
	d.record(path, out)
	return out
}

// manifestEvidence collects the labels of manifests in slash's directory or any
// ancestor that vouch for framework.
func (d *Detector) manifestEvidence(slash, framework string) []string {
	var labels []string
	for dir := dirOf(slash); ; {
		for _, h := range d.byDir[dir] {
			if h.framework == framework {
				labels = append(labels, h.label)
			}
		}
		parent := dirOf(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return labels
}

func (d *Detector) record(path string, det []Detected) {
	if len(det) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, x := range det {
		k := x.Framework + "|" + x.Confidence
		if d.files[k] == nil {
			d.files[k] = map[string]bool{}
		}
		d.files[k][path] = true
	}
}

// Summaries returns the per-framework, per-confidence file counts of every
// Detect call so far, sorted by framework then confidence. Nil when nothing
// was detected.
func (d *Detector) Summaries() []Summary {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Summary
	for k, set := range d.files {
		i := strings.IndexByte(k, '|')
		out = append(out, Summary{Framework: k[:i], Confidence: k[i+1:], Files: len(set)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		return out[i].Confidence < out[j].Confidence
	})
	return out
}

// HighHits returns the high-confidence detections in the IR's own type, for
// ir.IRFile.Frameworks.
func HighHits(det []Detected) []ir.FrameworkHit {
	var out []ir.FrameworkHit
	for _, x := range det {
		if x.Confidence == High {
			out = append(out, ir.FrameworkHit{Name: x.Framework, Evidence: x.Evidence})
		}
	}
	return out
}

// MediumHits returns the medium-confidence detections in the IR's own type,
// for ir.IRFile.FrameworksMedium.
func MediumHits(det []Detected) []ir.FrameworkHit {
	var out []ir.FrameworkHit
	for _, x := range det {
		if x.Confidence == Medium {
			out = append(out, ir.FrameworkHit{Name: x.Framework, Evidence: x.Evidence})
		}
	}
	return out
}

// AllNames returns the names of every detection, high or medium.
func AllNames(det []Detected) []string {
	out := make([]string, 0, len(det))
	for _, x := range det {
		out = append(out, x.Framework)
	}
	return out
}
