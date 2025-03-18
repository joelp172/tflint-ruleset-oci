package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// OCINetworkSecurityGroupSSHRule checks if OCI network security group allows unrestricted ingress access to port 22
type OCINetworkSecurityGroupSSHRule struct {
	tflint.DefaultRule
}

// NewOCINetworkSecurityGroupSSHRule returns a new rule
func NewOCINetworkSecurityGroupSSHRule() *OCINetworkSecurityGroupSSHRule {
	return &OCINetworkSecurityGroupSSHRule{}
}

// Name returns the rule name
func (r *OCINetworkSecurityGroupSSHRule) Name() string {
	return "oci_network_security_group_ssh"
}

// Enabled returns whether the rule is enabled by default
func (r *OCINetworkSecurityGroupSSHRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *OCINetworkSecurityGroupSSHRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *OCINetworkSecurityGroupSSHRule) Link() string {
	return "https://docs.oracle.com/en-us/iaas/Content/Security/Reference/networksecurity_topic.htm"
}

// Check checks if OCI network security group allows unrestricted ingress access to port 22
func (r *OCINetworkSecurityGroupSSHRule) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent("oci_core_network_security_group_security_rule", &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "direction"},
			{Name: "source"},
			{Name: "protocol"},
		},
		Blocks: []hclext.BlockSchema{
			{
				Type: "tcp_options",
				Body: &hclext.BodySchema{
					Blocks: []hclext.BlockSchema{
						{
							Type: "destination_port_range",
							Body: &hclext.BodySchema{
								Attributes: []hclext.AttributeSchema{
									{Name: "min"},
									{Name: "max"},
								},
							},
						},
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
		
		// Check direction
		dirAttr, exists := resource.Body.Attributes["direction"]
		if !exists {
			continue
		}
		
		var direction string
		err := runner.EvaluateExpr(dirAttr.Expr, &direction, nil)
		if err != nil {
			return err
		}
		
		if direction != "INGRESS" {
			continue
		}
		
		// Check source
		sourceAttr, exists := resource.Body.Attributes["source"]
		if !exists {
			continue
		}
		
		var source string
		err = runner.EvaluateExpr(sourceAttr.Expr, &source, nil)
		if err != nil {
			return err
		}
		
		if source != "0.0.0.0/0" {
			continue
		}
		
		// Check protocol
		protocolAttr, exists := resource.Body.Attributes["protocol"]
		if !exists {
			continue
		}
		
		var protocol string
		err = runner.EvaluateExpr(protocolAttr.Expr, &protocol, nil)
		if err != nil {
			return err
		}
		
		if protocol != "6" && protocol != "all" { // 6 is TCP
			continue
		}
		
		// Check port ranges
		var tcpOptions hclext.Blocks
		for _, block := range resource.Body.Blocks {
			if block.Type == "tcp_options" {
				tcpOptions = append(tcpOptions, block)
			}
		}
		for _, tcpOption := range tcpOptions {
			var portRanges hclext.Blocks
			for _, block := range tcpOption.Body.Blocks {
				if block.Type == "destination_port_range" {
					portRanges = append(portRanges, block)
				}
			}
			
			for _, portRange := range portRanges {
				minAttr, minExists := portRange.Body.Attributes["min"]
				maxAttr, maxExists := portRange.Body.Attributes["max"]
				
				if !minExists || !maxExists {
					continue
				}
				
				var min, max int
				err = runner.EvaluateExpr(minAttr.Expr, &min, nil)
				if err != nil {
					return err
				}
				
				err = runner.EvaluateExpr(maxAttr.Expr, &max, nil)
				if err != nil {
					return err
				}
				
				// Check if port 22 is in range
				if min <= 22 && max >= 22 {
					runner.EmitIssue(
						r,
						fmt.Sprintf("OCI Security Group rule '%s' allows unrestricted ingress access to port 22", addr),
						resource.DefRange,
					)
				}
			}
		}
	}
	return nil
}