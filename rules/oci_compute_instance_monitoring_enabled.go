package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// OCIComputeInstanceMonitoringRule checks if OCI Compute Instance has monitoring enabled
type OCIComputeInstanceMonitoringRule struct {
	tflint.DefaultRule
}

// NewOCIComputeInstanceMonitoringRule returns a new rule
func NewOCIComputeInstanceMonitoringRule() *OCIComputeInstanceMonitoringRule {
	return &OCIComputeInstanceMonitoringRule{}
}

// Name returns the rule name
func (r *OCIComputeInstanceMonitoringRule) Name() string {
	return "oci_compute_instance_monitoring"
}

// Enabled returns whether the rule is enabled by default
func (r *OCIComputeInstanceMonitoringRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *OCIComputeInstanceMonitoringRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *OCIComputeInstanceMonitoringRule) Link() string {
	return "https://docs.oracle.com/en-us/iaas/Content/Monitoring/Concepts/monitoringoverview.htm"
}

// Check checks if OCI Compute Instance has monitoring enabled
func (r *OCIComputeInstanceMonitoringRule) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent("oci_core_instance", &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "agent_config",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "is_monitoring_disabled"},
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
		var agentConfigs hclext.Blocks
		for _, block := range resource.Body.Blocks {
			if block.Type == "agent_config" {
				agentConfigs = append(agentConfigs, block)
			}
		}

		// Check if agent_config block exists
		if len(agentConfigs) == 0 {
			runner.EmitIssue(
				r,
				fmt.Sprintf("OCI Compute Instance '%s' does not have monitoring enabled", addr),
				resource.DefRange,
			)
			continue
		}

		for _, config := range agentConfigs {
			attr, exists := config.Body.Attributes["is_monitoring_disabled"]
			if !exists {
				runner.EmitIssue(
					r,
					fmt.Sprintf("OCI Compute Instance '%s' does not have monitoring enabled", addr),
					resource.DefRange,
				)
				continue
			}

			var disabled bool
			err := runner.EvaluateExpr(attr.Expr, &disabled, nil)
			if err != nil {
				return err
			}

			if disabled {
				runner.EmitIssue(
					r,
					fmt.Sprintf("OCI Compute Instance '%s' does not have monitoring enabled", addr),
					attr.Expr.Range(),
				)
			}
		}
	}
	return nil
}