package rules

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_OCIObjectStorageBucketPublicAccess(t *testing.T) {
	cases := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "Public access type ObjectRead",
			Content: `
resource "oci_objectstorage_bucket" "test" {
	access_type = "ObjectRead"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIObjectStorageBucketPublicAccessRule(),
					Message: "OCI Object Storage Bucket 'oci_objectstorage_bucket' is publicly accessible",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 3, Column: 16},
						End:      hcl.Pos{Line: 3, Column: 28},
					},
				},
			},
		},
		{
			Name: "Public access type ObjectReadWithoutList",
			Content: `
resource "oci_objectstorage_bucket" "test" {
	access_type = "ObjectReadWithoutList"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIObjectStorageBucketPublicAccessRule(),
					Message: "OCI Object Storage Bucket 'oci_objectstorage_bucket' is publicly accessible",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 3, Column: 16},
						End:      hcl.Pos{Line: 3, Column: 39},
					},
				},
			},
		},
		{
			Name: "NoPublicAccess is allowed",
			Content: `
resource "oci_objectstorage_bucket" "test" {
	access_type = "NoPublicAccess"
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "Missing access_type should emit warning",
			Content: `
resource "oci_objectstorage_bucket" "test" {
	# access_type not specified
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIObjectStorageBucketPublicAccessRule(),
					Message: "OCI Object Storage Bucket 'oci_objectstorage_bucket' does not explicitly set access_type to NoPublicAccess",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 43},
					},
				},
			},
		},
		{
			Name: "Variable for access_type",
			Content: `
variable "access_type" {
	default = "ObjectRead"
}

resource "oci_objectstorage_bucket" "test" {
	access_type = var.access_type
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIObjectStorageBucketPublicAccessRule(),
					Message: "OCI Object Storage Bucket 'oci_objectstorage_bucket' is publicly accessible",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 7, Column: 16},
						End:      hcl.Pos{Line: 7, Column: 31},
					},
				},
			},
		},
	}

	rule := NewOCIObjectStorageBucketPublicAccessRule()

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"main.tf": tc.Content})
			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, tc.Expected, runner.Issues)
		})
	}
}
