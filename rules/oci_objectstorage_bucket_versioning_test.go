package rules

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

// Test for OCIObjectStorageBucketVersioningRule
func TestOCIObjectStorageBucketVersioningRule(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "versioning enabled",
			Content: `
resource "oci_objectstorage_bucket" "test" {
  name       = "test_bucket"
  versioning = "Enabled"
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "versioning not enabled",
			Content: `
resource "oci_objectstorage_bucket" "test" {
  name       = "test_bucket"
  versioning = "Disabled"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIObjectStorageBucketVersioningRule(),
					Message: strings.Join([]string{
						"OCI Object Storage Bucket '",
						"oci_objectstorage_bucket",
						"' does not have object versioning enabled",
					}, ""),
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 4, Column: 16},
						End:      hcl.Pos{Line: 4, Column: 26},
					},
				},
			},
		},
		{
			Name: "versioning attribute missing",
			Content: `
resource "oci_objectstorage_bucket" "test" {
  name = "test_bucket"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIObjectStorageBucketVersioningRule(),
					Message: strings.Join([]string{
						"OCI Object Storage Bucket '",
						"oci_objectstorage_bucket",
						"' does not have object versioning enabled",
					}, ""),
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 43},
					},
				},
			},
		},
	}

	rule := NewOCIObjectStorageBucketVersioningRule()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"main.tf": test.Content})

			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}
