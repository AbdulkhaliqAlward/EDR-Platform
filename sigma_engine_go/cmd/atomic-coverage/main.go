// atomic-coverage inventories candidates; it never executes Atomic tests or endpoint actions.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/config"
	"gopkg.in/yaml.v3"
)

type atomicTest struct{ GUID, Technique, Name, Executor string }

func readIndex(r io.Reader) ([]atomicTest, error) {
	c := csv.NewReader(r)
	header, err := c.Read()
	if err != nil {
		return nil, err
	}
	columns := map[string]int{}
	for i, h := range header {
		columns[strings.TrimPrefix(h, "\ufeff")] = i
	}
	for _, name := range []string{"Test GUID", "Technique #", "Test Name", "Executor Name"} {
		if _, ok := columns[name]; !ok {
			return nil, fmt.Errorf("missing CSV column %q", name)
		}
	}
	seen := map[string]atomicTest{}
	for {
		row, err := c.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		t := atomicTest{strings.TrimSpace(row[columns["Test GUID"]]), strings.ToUpper(strings.TrimSpace(row[columns["Technique #"]])), row[columns["Test Name"]], row[columns["Executor Name"]]}
		if t.GUID == "" || t.Technique == "" {
			return nil, fmt.Errorf("empty test GUID or technique")
		}
		if prior, ok := seen[t.GUID]; ok && prior != t {
			return nil, fmt.Errorf("conflicting rows for GUID %s", t.GUID)
		}
		seen[t.GUID] = t // Tactic rows repeat the same test; do not inflate coverage.
	}
	result := make([]atomicTest, 0, len(seen))
	for _, t := range seen {
		result = append(result, t)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].GUID < result[j].GUID })
	return result, nil
}

func candidates(technique string, rs []*domain.SigmaRule) (exact, parent, sources []string) {
	sourceSet := map[string]bool{}
	for _, r := range rs {
		match, broad := false, false
		for _, tag := range r.MITRETechniques() {
			tag = strings.ToUpper(tag)
			match = match || tag == technique
			broad = broad || (strings.Contains(technique, ".") && tag == strings.SplitN(technique, ".", 2)[0])
		}
		if match {
			exact = append(exact, r.ID)
		} else if broad {
			parent = append(parent, r.ID)
		}
		if match || broad {
			category, service := "any", "any"
			if r.LogSource.Category != nil {
				category = *r.LogSource.Category
			}
			if r.LogSource.Service != nil {
				service = *r.LogSource.Service
			}
			sourceSet[category+"/"+service] = true
		}
	}
	for s := range sourceSet {
		sources = append(sources, s)
	}
	sort.Strings(exact)
	sort.Strings(parent)
	sort.Strings(sources)
	return
}

func run() error {
	indexPath := flag.String("index", "", "Official Atomic windows-index.csv (required; inert data only)")
	configPath := flag.String("config", "config/config.yaml", "Local rule loading configuration")
	revision := flag.String("revision", "unknown", "Atomic source revision; use the actual downloaded revision")
	out := flag.String("out", "atomic-coverage.csv", "New output CSV path (will not overwrite)")
	flag.Parse()
	data, err := os.ReadFile(*indexPath)
	if err != nil {
		return err
	}
	tests, err := readIndex(strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	configData, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	var cfg struct {
		Rules config.RulesConfig `yaml:"rules"`
	}
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		return err
	}
	if cfg.Rules.RulesDirectory == "" {
		return fmt.Errorf("rules.rules_directory is required")
	}
	loader := rules.NewRuleLoader(false)
	loader.SetProductWhitelist(cfg.Rules.ProductWhitelist)
	loader.SetQualityFilter(&rules.QualityFilter{MinLevel: cfg.Rules.MinLevel, AllowedStatus: cfg.Rules.AllowedStatus, SkipExperimental: cfg.Rules.SkipExperimentalEnabled()})
	idx, err := loader.LoadRules(context.Background(), cfg.Rules.RulesDirectory)
	if err != nil {
		return err
	}
	usable := []*domain.SigmaRule{}
	rejected := map[string]string{}
	for _, r := range idx.Rules {
		if err := detection.ValidateRule(r); err != nil {
			rejected[r.ID] = err.Error()
		} else {
			usable = append(usable, r)
		}
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if err := w.Write([]string{"test_guid", "technique", "test_name", "executor", "status", "exact_technique_candidate_rule_ids", "parent_technique_candidate_rule_ids", "required_rule_category/service", "endpoint_response"}); err != nil {
		f.Close()
		return err
	}
	counts := map[string]int{}
	for _, t := range tests {
		exact, parent, sources := candidates(t.Technique, usable)
		status := "no_tagged_candidate"
		if len(exact) > 0 {
			status = "candidate_unverified"
		} else if len(parent) > 0 {
			status = "parent_candidate_only_unverified"
		}
		counts[status]++
		if err := w.Write([]string{t.GUID, t.Technique, t.Name, t.Executor, status, strings.Join(exact, ";"), strings.Join(parent, ";"), strings.Join(sources, ";"), "unverified_policy_and_target_dependent"}); err != nil {
			f.Close()
			return err
		}
	}
	w.Flush()
	writeErr := w.Error()
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	hash := sha256.Sum256(data)
	return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"atomic_revision": *revision, "index_sha256": hex.EncodeToString(hash[:]), "unique_windows_tests": len(tests), "candidate_counts": counts, "compiled_eligible_disk_rules": len(usable), "compile_rejected": rejected, "loader_error_count": len(idx.Errors), "scope": "Disk rules only; ATT&CK tags are candidates, not per-test detection evidence. Runtime DB overrides, telemetry and responses are not verified."})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
