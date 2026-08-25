package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// parseHTTPXFindTarget extracts per-target recon facts from an httpxfind scan
// result. Shape: {"services":[{url,host,port,scheme,server,status_code,title,
// content_type,...}]}. Each ServiceResult is matched to the normalized target
// via EITHER its host field or its url. Every httpxfind finding is a recon fact
// (SevRank -1, empty Severity):
//
//	services[]      -> CatServices (Title = server, else "<scheme> service";
//	                                Detail = title; Locus = "<port>")
//	services[].port -> CatPorts    (Title = "<port>/tcp <scheme>")
//
// scanID is part of the contract but ignored here (the engine wires the link).
func parseHTTPXFindTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Services []struct {
			Host       string `json:"host"`
			Port       int    `json:"port"`
			URL        string `json:"url"`
			Scheme     string `json:"scheme"`
			StatusCode int    `json:"status_code"`
			Title      string `json:"title"`
			Server     string `json:"server"`
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxEmit = 1000
	emitted := 0

	for _, svc := range res.Services {
		if emitted >= maxEmit {
			return
		}
		// Match on either the service's host field or its url.
		if normalizeAsset(svc.Host) != target && !urlMatchesAsset(svc.URL, target) {
			continue
		}

		scheme := strings.TrimSpace(svc.Scheme)

		// Service fact — Server header, else a generic "<scheme> service".
		svcTitle := strings.TrimSpace(svc.Server)
		if svcTitle == "" {
			if scheme != "" {
				svcTitle = scheme + " service"
			} else {
				svcTitle = "http service"
			}
		}
		emit(targetRaw{
			Module:   "httpxfind",
			Category: CatServices,
			Title:    svcTitle,
			Detail:   strings.TrimSpace(svc.Title),
			Locus:    fmt.Sprintf("%d", svc.Port),
			Severity: "",
			SevRank:  -1,
		}, scanDate)
		emitted++

		// Port fact.
		if svc.Port > 0 && emitted < maxEmit {
			portTitle := fmt.Sprintf("%d/tcp", svc.Port)
			if scheme != "" {
				portTitle = fmt.Sprintf("%d/tcp %s", svc.Port, scheme)
			}
			locus := strings.TrimSpace(svc.URL)
			if locus == "" {
				locus = strings.TrimSpace(svc.Host)
			}
			emit(targetRaw{
				Module:   "httpxfind",
				Category: CatPorts,
				Title:    portTitle,
				Detail:   "",
				Locus:    locus,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
			emitted++
		}
	}
}
