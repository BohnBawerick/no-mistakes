package steps

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kunchenguid/no-mistakes/internal/types"
)

const maxGateFindingsBytes = 1 << 20
const maxGateFindings = 500

// readGateFindings distinguishes an untouched file from an explicit report.
// A broken report never falls back to the command's exit-code verdict.
func readGateFindings(path string) ([]Finding, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, fmt.Errorf("read findings file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("findings file must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("open findings file: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxGateFindingsBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read findings file: %w", err)
	}
	if len(raw) > maxGateFindingsBytes {
		return nil, false, fmt.Errorf("findings file exceeds 1 MiB")
	}
	if len(raw) == 0 {
		return nil, false, nil
	}
	var report struct {
		Items *[]Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, true, fmt.Errorf("parse findings JSON: %w", err)
	}
	if report.Items == nil {
		return nil, true, fmt.Errorf("missing findings array")
	}
	items := *report.Items
	if len(items) > maxGateFindings {
		return nil, true, fmt.Errorf("findings array exceeds 500 findings")
	}
	ids := make(map[string]bool, len(items))
	for i := range items {
		item := &items[i]
		item.ID = strings.TrimSpace(item.ID)
		if item.ID == "" || ids[item.ID] {
			return nil, true, fmt.Errorf("finding %d has a missing or duplicate id", i+1)
		}
		ids[item.ID] = true
		item.Severity = types.NormalizeFindingSeverity(item.Severity)
		if !types.IsKnownFindingSeverity(item.Severity) {
			return nil, true, fmt.Errorf("finding %q has an invalid severity", item.ID)
		}
		if strings.TrimSpace(item.Description) == "" {
			return nil, true, fmt.Errorf("finding %q is missing a description", item.ID)
		}
		if item.Line < 0 {
			return nil, true, fmt.Errorf("finding %q has a negative line", item.ID)
		}
		item.Action = types.NormalizeFindingAction(item.Action)
		item.Action = item.ActionOrDefault()
		if !types.IsKnownFindingAction(item.Action) {
			return nil, true, fmt.Errorf("finding %q has an invalid action", item.ID)
		}
	}
	return items, true, nil
}
