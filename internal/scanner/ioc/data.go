package ioc

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed data/ioc.yaml
var dataYAML []byte

type compromisedAction struct {
	Action   string `yaml:"action"`
	Advisory string `yaml:"advisory"`
	Summary  string `yaml:"summary"`
}

type urlPattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
	re    *regexp.Regexp
}

type dataFile struct {
	Payload struct {
		Executors []string `yaml:"executors"`
		Decoders  []string `yaml:"decoders"`
	} `yaml:"payload"`
	Webshell struct {
		CodeSinks    []string `yaml:"code_sinks"`
		CommandSinks []string `yaml:"command_sinks"`
	} `yaml:"webshell"`
	Mining struct {
		PoolSchemes []string `yaml:"pool_schemes"`
		Binaries    []string `yaml:"binaries"`
	} `yaml:"mining"`
	Exfil struct {
		Domains     []string     `yaml:"domains"`
		URLPatterns []urlPattern `yaml:"url_patterns"`
	} `yaml:"exfil"`
	CompromisedActions []compromisedAction `yaml:"compromised_actions"`
}

// matchers are the regexes compiled once from the embedded data.
type matchers struct {
	data dataFile

	executor   *regexp.Regexp // group 1 = executor name
	decoder    *regexp.Regexp // a decoder call start
	codeSink   *regexp.Regexp
	cmdSink    *regexp.Regexp
	poolURL    *regexp.Regexp
	minerCmd   *regexp.Regexp
	actions    map[string]compromisedAction
	exfilHosts []string
}

func alt(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = regexp.QuoteMeta(n)
	}
	return strings.Join(q, "|")
}

func loadMatchers() (*matchers, error) {
	var d dataFile
	if err := yaml.Unmarshal(dataYAML, &d); err != nil {
		return nil, fmt.Errorf("ioc: embedded data: %w", err)
	}
	for i := range d.Exfil.URLPatterns {
		re, err := regexp.Compile(d.Exfil.URLPatterns[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("ioc: exfil pattern %s: %w", d.Exfil.URLPatterns[i].Name, err)
		}
		d.Exfil.URLPatterns[i].re = re
	}
	m := &matchers{data: d, actions: map[string]compromisedAction{}}
	for _, a := range d.CompromisedActions {
		if a.Advisory == "" {
			return nil, fmt.Errorf("ioc: compromised action %s has no advisory id", a.Action)
		}
		m.actions[strings.ToLower(a.Action)] = a
	}
	m.executor = regexp.MustCompile(`(` + alt(d.Payload.Executors) + `)\s*\(`)
	m.decoder = regexp.MustCompile(`\b(?:` + alt(d.Payload.Decoders) + `)\s*\(|Buffer\.from\s*\([^)]*['"](?:base64|hex)['"]`)
	m.codeSink = regexp.MustCompile(`(?i)(?:^|[^\w$>:.])@?(` + alt(d.Webshell.CodeSinks) + `)\s*\(`)
	m.cmdSink = regexp.MustCompile(`(?i)(?:^|[^\w$>:.])@?(` + alt(d.Webshell.CommandSinks) + `)\s*\(`)
	schemes := make([]string, len(d.Mining.PoolSchemes))
	for i, s := range d.Mining.PoolSchemes {
		schemes[i] = regexp.QuoteMeta(s)
	}
	m.poolURL = regexp.MustCompile(`(?i)\b(?:` + strings.Join(schemes, "|") + `)://`)
	m.minerCmd = regexp.MustCompile(`(?i)(?:^|[\s/\\"'=;&|(])(?:` + alt(d.Mining.Binaries) + `)(?:\.exe)?["']?\s+(?:\S+\s+)*?(?:-o\s|--url[= ]|--donate-level|-a\s+\S+\s+-o\s)`)
	for _, h := range d.Exfil.Domains {
		m.exfilHosts = append(m.exfilHosts, strings.ToLower(h))
	}
	return m, nil
}
