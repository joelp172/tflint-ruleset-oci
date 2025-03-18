package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// OCIComputeInstanceInTransitEncryptionRule checks if OCI Compute Instance boot volume has in-transit data encryption enabled
type OCIComputeInstanceInTransitEncryptionRule struct {
	tflint.DefaultRule
}

// NewOCIComputeInstanceInTransitEncryptionRule returns a new rule
func NewOCIComputeInstanceInTransitEncryptionRule() *OCIComputeInstanceInTransitEncryptionRule {
	return &OCIComputeInstanceInTransitEncryptionRule{}
}

// Name returns the rule name
func (r *OCIComputeInstanceInTransitEncryptionRule) Name() string {
	return "oci_compute_instance_in_transit_encryption"
}

// Enabled returns whether the rule is enabled by default
func (r *OCIComputeInstanceInTransitEncryptionRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *OCIComputeInstanceInTransitEncryptionRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *OCIComputeInstanceInTransitEncryptionRule) Link() string {
	return "https://docs.oracle.com/en-us/iaas/Content/Security/Reference/security_recommendations.htm"
}

// Check checks if the OCI Compute Instance has boot volume in-transit data encryption enabled
func (r *OCIComputeInstanceInTransitEncryptionRule) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent("oci_core_instance", &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "launch_options",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "is_pv_encryption_in_transit_enabled"},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		addr := resource.Labels[0]
		var launchOptions hclext.Blocks
		for _, block := range resource.Body.Blocks {
			if block.Type == "launch_options" {
				launchOptions = append(launchOptions, block)
			}
		}

		// Check if launch_options block exists
		if len(launchOptions) == 0 {
			runner.EmitIssue(
				r,
				"OCI Compute Instance boot volume does not have in-transit data encryption enabled",
				resource.DefRange,
			)
			continue
		}

		for _, opts := range launchOptions {
			attr, exists := opts.Body.Attributes["is_pv_encryption_in_transit_enabled"]
			if !exists {
				runner.EmitIssue(
					r,
					fmt.Sprintf("OCI Compute Instance '%s' does not have boot volume in-transit data encryption enabled", addr),
					resource.DefRange,
				)
				continue
			}

			var enabled bool
			err := runner.EvaluateExpr(attr.Expr, &enabled, nil)
			if err != nil {
				return err
			}

			if !enabled {
				runner.EmitIssue(
					r,
					fmt.Sprintf("OCI Compute Instance '%s' does not have boot volume in-transit data encryption enabled", addr),
					attr.Expr.Range(),
				)
			}
		}
	}
	return nil
}
