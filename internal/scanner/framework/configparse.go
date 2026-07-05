package framework

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// EnvEntry is one KEY=VALUE (or Java-properties key=value) line.
type EnvEntry struct {
	Key   string
	Value string
	Line  int
}

// YAMLEntry is one leaf value from a flattened YAML document.
type YAMLEntry struct {
	Path  string // dotted path, e.g. "cors.origin"
	Value string
	Line  int
}

// ParseEnvFile parses dotenv-style KEY=VALUE lines, stripping "export ",
// surrounding quotes, and "#" comments.
func ParseEnvFile(data []byte) []EnvEntry {
	var out []EnvEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := splitKV(line, "=")
		if !ok {
			continue
		}
		out = append(out, EnvEntry{Key: key, Value: unquote(value), Line: lineNum})
	}
	return out
}

// ParseProperties parses Java-style "key=value" / "key: value" lines.
// v1 limitation: no backslash line-continuation support.
func ParseProperties(data []byte) []EnvEntry {
	var out []EnvEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		sep := "="
		if !strings.Contains(line, "=") && strings.Contains(line, ":") {
			sep = ":"
		}
		key, value, ok := splitKV(line, sep)
		if !ok {
			continue
		}
		out = append(out, EnvEntry{Key: key, Value: unquote(value), Line: lineNum})
	}
	return out
}

// ParseYAMLFlat parses a YAML document via yaml.Node (not a plain map) so
// leaf line numbers survive, and flattens nested mappings/sequences into
// dotted paths (e.g. "cors.origin").
func ParseYAMLFlat(data []byte) ([]YAMLEntry, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	var out []YAMLEntry
	flattenYAMLNode(doc.Content[0], "", &out)
	return out, nil
}

func flattenYAMLNode(node *yaml.Node, prefix string, out *[]YAMLEntry) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			val := node.Content[i+1]
			path := key.Value
			if prefix != "" {
				path = prefix + "." + key.Value
			}
			flattenYAMLNode(val, path, out)
		}
	case yaml.SequenceNode:
		for i, item := range node.Content {
			path := prefix + "." + strconv.Itoa(i)
			flattenYAMLNode(item, path, out)
		}
	case yaml.ScalarNode:
		*out = append(*out, YAMLEntry{Path: prefix, Value: node.Value, Line: node.Line})
	}
}

// splitKV splits "key<sep>value" on the first occurrence of sep, trimming
// surrounding whitespace from both parts. Returns ok=false if sep is absent.
func splitKV(line, sep string) (key, value string, ok bool) {
	idx := strings.Index(line, sep)
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+len(sep):])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

// unquote strips a single matching pair of surrounding quotes, if present.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
