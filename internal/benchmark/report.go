package benchmark

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// jsonReport is the machine-readable shape written to --json-out.
type jsonReport struct {
	TP         int                      `json:"tp"`
	FP         int                      `json:"fp"`
	FN         int                      `json:"fn"`
	Precision  float64                  `json:"precision"`
	Recall     float64                  `json:"recall"`
	ByRule     map[string]RuleStats     `json:"by_rule"`
	ByLanguage map[string]LangStats     `json:"by_language"`
	ByModality map[string]ModalityStats `json:"by_modality"`
}

// JSON renders the summary as indented JSON.
func (s *Summary) JSON() ([]byte, error) {
	r := jsonReport{
		TP: s.TP, FP: s.FP, FN: s.FN,
		Precision:  s.Precision(),
		Recall:     s.Recall(),
		ByRule:     make(map[string]RuleStats),
		ByLanguage: make(map[string]LangStats),
		ByModality: make(map[string]ModalityStats),
	}
	for k, v := range s.ByRule {
		r.ByRule[k] = *v
	}
	for k, v := range s.ByLanguage {
		r.ByLanguage[k] = *v
	}
	for k, v := range s.ByModality {
		r.ByModality[k] = *v
	}
	return json.MarshalIndent(r, "", "  ")
}

// Markdown renders a human-readable accuracy report.
func (s *Summary) Markdown(version string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Accuracy Report — %s\n\n", version)
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| True Positives | %d |\n", s.TP)
	fmt.Fprintf(&b, "| False Positives | %d |\n", s.FP)
	fmt.Fprintf(&b, "| False Negatives | %d |\n", s.FN)
	fmt.Fprintf(&b, "| Precision | %.2f%% |\n", s.Precision()*100)
	fmt.Fprintf(&b, "| Recall | %.2f%% |\n\n", s.Recall()*100)

	b.WriteString("## Per-Language Recall\n\n| Language | TP | FN | Recall |\n|---|---|---|---|\n")
	for _, lang := range sortedKeys(s.ByLanguage) {
		ls := s.ByLanguage[lang]
		fmt.Fprintf(&b, "| %s | %d | %d | %.2f%% |\n", lang, ls.TP, ls.FN, recallOf(ls.TP, ls.FN)*100)
	}

	b.WriteString("\n## Per-Modality\n\n| Modality | TP | FP | FN |\n|---|---|---|---|\n")
	for _, kind := range sortedKeys(s.ByModality) {
		ms := s.ByModality[kind]
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", kind, ms.TP, ms.FP, ms.FN)
	}

	b.WriteString("\n## Per-Rule Precision\n\n| Rule | TP | FP | Precision |\n|---|---|---|---|\n")
	for _, rule := range sortedKeys(s.ByRule) {
		rs := s.ByRule[rule]
		fmt.Fprintf(&b, "| %s | %d | %d | %.2f%% |\n", rule, rs.TP, rs.FP, precisionOf(rs.TP, rs.FP)*100)
	}

	var mismatches []CaseResult
	for _, c := range s.Cases {
		if c.FP > 0 || c.FN > 0 {
			mismatches = append(mismatches, c)
		}
	}
	if len(mismatches) > 0 {
		b.WriteString("\n## Mismatches\n\n")
		for _, c := range mismatches {
			fmt.Fprintf(&b, "- **%s/%s**: %s\n", c.Dir, c.File, strings.Join(c.Notes, "; "))
		}
	}

	return b.String()
}

func recallOf(tp, fn int) float64 {
	if tp+fn == 0 {
		return 1
	}
	return float64(tp) / float64(tp+fn)
}

func precisionOf(tp, fp int) float64 {
	if tp+fp == 0 {
		return 1
	}
	return float64(tp) / float64(tp+fp)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
