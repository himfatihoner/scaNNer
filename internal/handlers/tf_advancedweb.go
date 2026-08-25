package handlers

import (
	"encoding/json"
	"time"
)

// parseAdvancedWebTarget fans a suite scan's nested per-stage results back
// through the same per-module parsers. Each StageResult.Result is the native
// module's own ScanResult JSON (json.RawMessage), keyed by a Stage name that
// equals the module slug — so we can re-dispatch it through
// dispatchTargetParser. The one exception is the "dirspider" stage, whose
// result bundles a direnum + a spider ScanResult under one object.
//
// Findings keep their sub-module's Module label (e.g. "nuclei"), so a suite
// finding dedupes/merges with an equivalent standalone-scan finding; the
// engine still links the sighting back to this advancedweb scan.
func parseAdvancedWebTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var r struct {
		Stages map[string]struct {
			Result json.RawMessage `json:"result"`
		} `json:"stages"`
	}
	if json.Unmarshal([]byte(resJSON), &r) != nil {
		return
	}
	for stage, sr := range r.Stages {
		if len(sr.Result) == 0 {
			continue
		}
		if stage == "dirspider" {
			var ds struct {
				DirEnum json.RawMessage `json:"direnum"`
				Spider  json.RawMessage `json:"spider"`
			}
			if json.Unmarshal(sr.Result, &ds) == nil {
				if len(ds.DirEnum) > 0 {
					parseDirEnumTarget(string(ds.DirEnum), target, scanDate, scanID, emit)
				}
				if len(ds.Spider) > 0 {
					parseSpiderTarget(string(ds.Spider), target, scanDate, scanID, emit)
				}
			}
			continue
		}
		dispatchTargetParser(stage, string(sr.Result), target, scanDate, scanID, emit)
	}
}
