// Go + wazero binding runner: same contract as `mcp-rbac-core vectors` (one output line per corpus vector).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"

	mcprbac "github.com/saarimz/mcp-rbac/go"
)

type vector struct {
	PolicyYAML   *string `json:"policyYaml"`
	PolicyJSON   *string `json:"policyJson"`
	YAMLDoc      *string `json:"yamlDoc"`
	RequestJSON  *string `json:"requestJson"`
	VisibleJSON  *string `json:"visibleJson"`
	CostJSON     *string `json:"costJson"`
	FeedbackJSON *string `json:"feedbackJson"`
}

func main() {
	ctx := context.Background()
	path := "conformance/corpus.jsonl"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	rt, err := mcprbac.NewRuntime(ctx)
	if err != nil {
		log.Fatal(err)
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	var (
		lastKey string
		eng     *mcprbac.Engine
		bad     bool
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	must := func(s string, err error) string {
		if err != nil {
			log.Fatal(err)
		}
		return s
	}
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var v vector
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			log.Fatal(err)
		}
		var out string
		if v.YAMLDoc != nil {
			out = must(rt.YAMLToJSON(ctx, *v.YAMLDoc))
		} else if v.CostJSON != nil {
			out = must(rt.Cost(ctx, *v.CostJSON))
		} else if v.FeedbackJSON != nil {
			out = must(rt.Feedback(ctx, *v.FeedbackJSON))
		} else {
			key := ""
			if v.PolicyYAML != nil {
				key = "y" + *v.PolicyYAML
			} else {
				key = "j" + *v.PolicyJSON
			}
			if key != lastKey { // one engine (= one wasm instance) at a time; corpus is grouped by policy
				if eng != nil {
					_ = eng.Close(ctx)
				}
				eng, bad, lastKey = nil, false, key
				if v.PolicyYAML != nil {
					eng, err = rt.NewEngine(ctx, *v.PolicyYAML)
				} else {
					eng, err = rt.NewEngineJSON(ctx, *v.PolicyJSON)
				}
				if errors.Is(err, mcprbac.ErrPolicy) {
					bad = true
				} else if err != nil {
					log.Fatal(err)
				}
			}
			switch {
			case bad:
				out = `{"error":"policy_invalid"}`
			case v.RequestJSON != nil:
				out = must(eng.Decide(ctx, *v.RequestJSON))
			case v.VisibleJSON != nil:
				out = must(eng.Visible(ctx, *v.VisibleJSON))
			default:
				out = `{"ok":true,"warnings":` + must(eng.Warnings(ctx)) + "}"
			}
		}
		w.WriteString(out)
		w.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		log.Fatal(err)
	}
}
