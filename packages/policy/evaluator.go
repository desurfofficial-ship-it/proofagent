package policy

import (
	"fmt"
	"strings"
)

const (
	Allow           = "ALLOW"
	Deny            = "DENY"
	RequireApproval = "REQUIRE_APPROVAL"
)

type Rule struct {
	Effect     string         `json:"effect"`
	Action     string         `json:"action"`
	Conditions map[string]any `json:"conditions,omitempty"`
}

type PolicyDocument struct {
	PolicyID string `json:"policy_id"`
	Version  int    `json:"version"`
	Rules    []Rule `json:"rules"`
}

type ActionRequest struct {
	Type    string         `json:"type"`
	Tool    string         `json:"tool"`
	Target  string         `json:"target,omitempty"`
	Context map[string]any `json:"context,omitempty"`
}

type Result struct {
	Decision  string
	RuleIndex int
	Reason    string
}

// Evaluate: DENY > REQUIRE_APPROVAL > ALLOW; default DENY.
func Evaluate(doc *PolicyDocument, req ActionRequest) Result {
	if doc == nil || len(doc.Rules) == 0 {
		return Result{Decision: Deny, RuleIndex: -1, Reason: "no_policy"}
	}

	actionKey := req.Tool
	if actionKey == "" {
		actionKey = req.Type
	}

	denyIdx, approvalIdx, allowIdx := -1, -1, -1

	for i, r := range doc.Rules {
		if !actionMatches(r.Action, actionKey) {
			continue
		}
		if !conditionsMatch(r.Conditions, req.Context) {
			continue
		}
		effect := strings.ToLower(strings.TrimSpace(r.Effect))
		switch effect {
		case "deny":
			if denyIdx < 0 {
				denyIdx = i
			}
		case "require_approval":
			if approvalIdx < 0 {
				approvalIdx = i
			}
		case "allow":
			if allowIdx < 0 {
				allowIdx = i
			}
		}
	}

	if denyIdx >= 0 {
		return Result{Decision: Deny, RuleIndex: denyIdx, Reason: "explicit_deny"}
	}
	if approvalIdx >= 0 {
		return Result{Decision: RequireApproval, RuleIndex: approvalIdx, Reason: "requires_approval"}
	}
	if allowIdx >= 0 {
		return Result{Decision: Allow, RuleIndex: allowIdx, Reason: "allowed"}
	}
	return Result{Decision: Deny, RuleIndex: -1, Reason: "default_deny"}
}

func actionMatches(pattern, action string) bool {
	if pattern == action {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		return strings.HasPrefix(action, prefix+".") || action == prefix
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(action, prefix)
	}
	return false
}

func conditionsMatch(conds map[string]any, ctx map[string]any) bool {
	if len(conds) == 0 {
		return true
	}
	if ctx == nil {
		ctx = map[string]any{}
	}
	amount := toFloat(ctx["amount"])

	for k, want := range conds {
		switch k {
		case "amount_gt":
			if amount <= toFloat(want) {
				return false
			}
		case "amount_gte":
			if amount < toFloat(want) {
				return false
			}
		case "amount_lt":
			if amount >= toFloat(want) {
				return false
			}
		case "amount_lte":
			if amount > toFloat(want) {
				return false
			}
		case "recipient_domain":
			got, _ := ctx["recipient_domain"]
			if got == nil {
				got = ctx["recipient"]
			}
			domains := toStringSlice(want)
			gotStr := strings.ToLower(fmt.Sprint(got))
			matched := false
			for _, d := range domains {
				d = strings.ToLower(d)
				if gotStr == d || strings.HasSuffix(gotStr, "@"+d) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		default:
			got, ok := ctx[k]
			if !ok || fmt.Sprint(got) != fmt.Sprint(want) {
				return false
			}
		}
	}
	return true
}

func toFloat(v any) float64 {
	if v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case int32:
		return float64(n)
	default:
		var f float64
		_, _ = fmt.Sscanf(fmt.Sprint(v), "%f", &f)
		return f
	}
}

func toStringSlice(v any) []string {
	switch s := v.(type) {
	case string:
		return []string{s}
	case []any:
		out := make([]string, 0, len(s))
		for _, el := range s {
			out = append(out, fmt.Sprint(el))
		}
		return out
	case []string:
		return s
	default:
		return []string{fmt.Sprint(v)}
	}
}
