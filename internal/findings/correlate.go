package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// Metadata keys written by Correlate on findings that are part of a taint chain.
const (
	MetaChainID     = "chain_id"     // stable short id shared by every finding in the chain
	MetaChainSize   = "chain_size"   // number of findings in the chain
	MetaChainSource = "chain_source" // the shared tainted source variable
	MetaChainRules  = "chain_rules"  // comma-separated sorted distinct rule IDs in the chain
)

// Correlate links SAST findings in the same file that share the same tainted
// source variable: one untrusted input reaching two or more sinks is an
// attack chain (e.g. the same user-controlled path hitting a read-traversal
// sink and a file-write sink). Chained findings get chain_* Metadata entries
// (see the Meta* constants); everything else is left untouched.
//
// ponytail: same-file + same-source-var only — cross-file chains would need
// cross-file taint tracking the engine doesn't have.
func Correlate(all []core.Finding) {
	groups := make(map[string][]int)
	for i, f := range all {
		if f.Kind != core.FindingKindSAST || f.TaintContext == nil || f.TaintContext.SourceVar == "" {
			continue
		}
		key := f.Location.File + "|" + f.TaintContext.SourceVar
		groups[key] = append(groups[key], i)
	}

	for key, idxs := range groups {
		if len(idxs) < 2 {
			continue
		}
		ruleSet := make(map[string]struct{}, len(idxs))
		for _, i := range idxs {
			ruleSet[all[i].RuleID] = struct{}{}
		}
		ruleIDs := make([]string, 0, len(ruleSet))
		for id := range ruleSet {
			ruleIDs = append(ruleIDs, id)
		}
		sort.Strings(ruleIDs)

		h := sha256.Sum256([]byte(key))
		chainID := hex.EncodeToString(h[:])[:12]

		for _, i := range idxs {
			if all[i].Metadata == nil {
				all[i].Metadata = make(map[string]string, 4)
			}
			all[i].Metadata[MetaChainID] = chainID
			all[i].Metadata[MetaChainSize] = strconv.Itoa(len(idxs))
			all[i].Metadata[MetaChainSource] = all[i].TaintContext.SourceVar
			all[i].Metadata[MetaChainRules] = strings.Join(ruleIDs, ",")
		}
	}
}
