package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// OCIObjectStorageBucketPublicAccessRule checks if OCI Object Storage bucket is publicly accessible
type OCIObjectStorageBucketPublicAccessRule struct {
	tflint.DefaultRule
}

// NewOCIObjectStorageBucketPublicAccessRule returns a new rule
func NewOCIObjectStorageBucketPublicAccessRule() *OCIObjectStorageBucketPublicAccessRule {
	return &OCIObjectStorageBucketPublicAccessRule{}
}

// Name returns the rule name
func (r *OCIObjectStorageBucketPublicAccessRule) Name() string {
	return "oci_object_storage_bucket_public_access"
}

// Enabled returns whether the rule is enabled by default
func (r *OCIObjectStorageBucketPublicAccessRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *OCIObjectStorageBucketPublicAccessRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *OCIObjectStorageBucketPublicAccessRule) Link() string {
	return "https://docs.oracle.com/en-us/iaas/Content/Security/Reference/objectstorage_security.htm"
}

// Check checks if OCI Object Storage bucket is publicly accessible
func (r *OCIObjectStorageBucketPublicAccessRule) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent("oci_objectstorage_bucket", &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "access_type"},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		addr := resource.Labels[0]
		attr, exists := resource.Body.Attributes["access_type"]
		
		if !exists {
			// Default is usually NoPublicAccess, but we should warn anyway
			runner.EmitIssue(
				r,
				fmt.Sprintf("OCI Object Storage Bucket '%s' does not explicitly set access_type to NoPublicAccess", addr),
				resource.DefRange,
			)
			continue
		}

		var accessType string
		err := runner.EvaluateExpr(attr.Expr, &accessType, nil)
		if err != nil {
			return err
		}

		if accessType != "NoPublicAccess" {
			runner.EmitIssue(
				r,
				fmt.Sprintf("OCI Object Storage Bucket '%s' is publicly accessible", addr),
				attr.Expr.Range(),
			)
		}
	}
	return nil
}