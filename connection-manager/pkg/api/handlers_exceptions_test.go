package api

import (
	"testing"

	"github.com/edr-platform/connection-manager/internal/repository"
)

func cond(field, op, value string) repository.ExceptionCondition {
	return repository.ExceptionCondition{Field: field, Op: op, Value: value}
}

func TestValidateExceptionConditions(t *testing.T) {
	img := `C:\Program Files\Backup\agent.exe`
	cases := []struct {
		name   string
		conds  []repository.ExceptionCondition
		global bool
		ok     bool
	}{
		{"rule-scoped command-line contains", []repository.ExceptionCondition{cond("CommandLine", "contains", "--nightly")}, false, true},
		{"no conditions", nil, false, false},
		{"unknown field", []repository.ExceptionCondition{cond("Foo", "equals", "x")}, false, false},
		{"regex operator", []repository.ExceptionCondition{cond("Image", "regex", ".*")}, false, false},
		{"wildcard value", []repository.ExceptionCondition{cond("Image", "equals", `C:\*`)}, false, false},
		{"too-short partial", []repository.ExceptionCondition{cond("CommandLine", "contains", "-c")}, false, false},
		{"global without anchor", []repository.ExceptionCondition{cond("CommandLine", "contains", "--nightly")}, true, false},
		{"global with exact image", []repository.ExceptionCondition{cond("Image", "equals", img), cond("CommandLine", "contains", "--nightly")}, true, true},
		{"global with endswith image is not an anchor", []repository.ExceptionCondition{cond("Image", "endswith", `\agent.exe`)}, true, false},
		{"control characters", []repository.ExceptionCondition{cond("Image", "equals", "a\x00b")}, false, false},
	}
	for _, tc := range cases {
		_, err := validateExceptionConditions(tc.conds, tc.global)
		if (err == nil) != tc.ok {
			t.Errorf("%s: ok=%v err=%v", tc.name, tc.ok, err)
		}
	}
	out, err := validateExceptionConditions([]repository.ExceptionCondition{cond(" Image ", " EQUALS ", "  "+img+" ")}, true)
	if err != nil || out[0].Field != "Image" || out[0].Op != "equals" || out[0].Value != img {
		t.Fatalf("conditions must be normalised: %+v %v", out, err)
	}
}
