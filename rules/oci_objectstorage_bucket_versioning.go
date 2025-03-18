package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// OCIObjectStorageBucketVersioningRule checks if OCI Object Storage Bucket has object Versioning enabled
type OCIObjectStorageBucketVersioningRule struct {
	tflint.DefaultRule
}

// NewOCIObjectStorageBucketVersioningRule returns a new rule
func NewOCIObjectStorageBucketVersioningRule() *OCIObjectStorageBucketVersioningRule {
	return &OCIObjectStorageBucketVersioningRule{}
}

// Name returns the rule name
func (r *OCIObjectStorageBucketVersioningRule) Name() string {
	return "oci_object_storage_bucket_versioning"
}

// Enabled returns whether the rule is enabled by default
func (r *OCIObjectStorageBucketVersioningRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *OCIObjectStorageBucketVersioningRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *OCIObjectStorageBucketVersioningRule) Link() string {
	return "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingversioning.htm"
}

// Check checks if OCI Object Storage Bucket has object Versioning enabled
func (r *OCIObjectStorageBucketVersioningRule) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent("oci_objectstorage_bucket", &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "versioning"},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		addr := resource.Labels[0]
		attr, exists := resource.Body.Attributes["versioning"]
		
		if !exists {
			runner.EmitIssue(
				r,
				fmt.Sprintf("OCI Object Storage Bucket '%s' does not have object versioning enabled", addr),
				resource.DefRange,
			)
			continue
		}

		var versioning string
		err := runner.EvaluateExpr(attr.Expr, &versioning, nil)
		if err != nil {
			return err
		}

		if versioning != "Enabled" {
			runner.EmitIssue(
				r,
				fmt.Sprintf("OCI Object Storage Bucket '%s' does not have object versioning enabled", addr),
				attr.Expr.Range(),
			)
		}
	}
	return nil
}
