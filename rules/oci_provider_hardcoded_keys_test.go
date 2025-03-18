package rules

import (
	"testing"

	"github.com/terraform-linters/tflint-plugin-sdk/helper"
	"github.com/hashicorp/hcl/v2"
)

// Test for OCIProviderHardcodedKeysRule
func TestOCIProviderHardcodedKeysRule(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "hardcoded key password",
			Content: `
provider "oci" {
  private_key_password = "hardcoded_password"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIProviderHardcodedKeysRule(),
					Message: "OCI provider has hard-coded private key password",
					Range: hcl.Range{
						Filename: "provider.tf",
						Start:    hcl.Pos{Line: 3, Column: 26},
						End:      hcl.Pos{Line: 3, Column: 46},
					},
				},
			},
		},
		{
			Name: "no hardcoded key password",
			Content: `
provider "oci" {
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewOCIProviderHardcodedKeysRule()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"provider.tf": test.Content})

			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}