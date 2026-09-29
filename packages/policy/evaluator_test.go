package policy

import "testing"

func demoPolicy() *PolicyDocument {
	return &PolicyDocument{
		PolicyID: "pol_demo",
		Version:  4,
		Rules: []Rule{
			{Effect: "allow", Action: "calendar.read"},
			{Effect: "allow", Action: "email.send", Conditions: map[string]any{
				"recipient_domain": []any{"company.com"},
			}},
			{Effect: "deny", Action: "stripe.create_payment", Conditions: map[string]any{
				"amount_gt": 100,
			}},
			{Effect: "require_approval", Action: "stripe.create_payment", Conditions: map[string]any{
				"amount_gte": 50,
			}},
			{Effect: "allow", Action: "stripe.create_payment"},
		},
	}
}

func TestEvaluate_AllowCalendar(t *testing.T) {
	r := Evaluate(demoPolicy(), ActionRequest{Tool: "calendar.read"})
	if r.Decision != Allow {
		t.Fatalf("got %s reason %s", r.Decision, r.Reason)
	}
}

func TestEvaluate_DenyOverLimit(t *testing.T) {
	r := Evaluate(demoPolicy(), ActionRequest{
		Tool:    "stripe.create_payment",
		Context: map[string]any{"amount": 400},
	})
	if r.Decision != Deny {
		t.Fatalf("got %s reason %s", r.Decision, r.Reason)
	}
}

func TestEvaluate_RequireApproval(t *testing.T) {
	r := Evaluate(demoPolicy(), ActionRequest{
		Tool:    "stripe.create_payment",
		Context: map[string]any{"amount": 75},
	})
	if r.Decision != RequireApproval {
		t.Fatalf("got %s reason %s", r.Decision, r.Reason)
	}
}

func TestEvaluate_AllowSmallPayment(t *testing.T) {
	r := Evaluate(demoPolicy(), ActionRequest{
		Tool:    "stripe.create_payment",
		Context: map[string]any{"amount": 25},
	})
	if r.Decision != Allow {
		t.Fatalf("got %s reason %s", r.Decision, r.Reason)
	}
}

func TestEvaluate_DefaultDeny(t *testing.T) {
	r := Evaluate(demoPolicy(), ActionRequest{Tool: "unknown.tool"})
	if r.Decision != Deny || r.Reason != "default_deny" {
		t.Fatalf("got %s %s", r.Decision, r.Reason)
	}
}

func TestEvaluate_EmailDomain(t *testing.T) {
	r := Evaluate(demoPolicy(), ActionRequest{
		Tool:    "email.send",
		Context: map[string]any{"recipient_domain": "company.com"},
	})
	if r.Decision != Allow {
		t.Fatalf("got %s", r.Decision)
	}
	r2 := Evaluate(demoPolicy(), ActionRequest{
		Tool:    "email.send",
		Context: map[string]any{"recipient_domain": "evil.com"},
	})
	if r2.Decision != Deny {
		t.Fatalf("got %s", r2.Decision)
	}
}
