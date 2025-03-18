package rules

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_OCINetworkSecurityGroupSSHRule(t *testing.T) {
	cases := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "SSH port open to 0.0.0.0/0",
			Content: `
resource "oci_core_network_security_group_security_rule" "test" {
	direction = "INGRESS"
	source = "0.0.0.0/0"
	protocol = "6"  # TCP
	
	tcp_options {
		destination_port_range {
			min = 22
			max = 22
		}
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCINetworkSecurityGroupSSHRule(),
					Message: "OCI Security Group rule 'oci_core_network_security_group_security_rule' allows unrestricted ingress access to port 22",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 64},
					},
				},
			},
		},
		{
			Name: "SSH port in wider range",
			Content: `
resource "oci_core_network_security_group_security_rule" "test" {
	direction = "INGRESS"
	source = "0.0.0.0/0"
	protocol = "6"  # TCP
	
	tcp_options {
		destination_port_range {
			min = 20
			max = 30
		}
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCINetworkSecurityGroupSSHRule(),
					Message: "OCI Security Group rule 'oci_core_network_security_group_security_rule' allows unrestricted ingress access to port 22",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 64},
					},
				},
			},
		},
		{
			Name: "All protocols open",
			Content: `
resource "oci_core_network_security_group_security_rule" "test" {
	direction = "INGRESS"
	source = "0.0.0.0/0"
	protocol = "all"
	
	tcp_options {
		destination_port_range {
			min = 22
			max = 22
		}
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCINetworkSecurityGroupSSHRule(),
					Message: "OCI Security Group rule 'oci_core_network_security_group_security_rule' allows unrestricted ingress access to port 22",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 64},
					},
				},
			},
		},
		{
			Name: "Not ingress rule",
			Content: `
resource "oci_core_network_security_group_security_rule" "test" {
	direction = "EGRESS"
	source = "0.0.0.0/0"
	protocol = "6"
	
	tcp_options {
		destination_port_range {
			min = 22
			max = 22
		}
	}
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "Not 0.0.0.0/0 source",
			Content: `
resource "oci_core_network_security_group_security_rule" "test" {
	direction = "INGRESS"
	source = "10.0.0.0/8"
	protocol = "6"
	
	tcp_options {
		destination_port_range {
			min = 22
			max = 22
		}
	}
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "Not TCP protocol",
			Content: `
resource "oci_core_network_security_group_security_rule" "test" {
	direction = "INGRESS"
	source = "0.0.0.0/0"
	protocol = "17"  # UDP
	
	tcp_options {
		destination_port_range {
			min = 22
			max = 22
		}
	}
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "Port range not including 22",
			Content: `
resource "oci_core_network_security_group_security_rule" "test" {
	direction = "INGRESS"
	source = "0.0.0.0/0"
	protocol = "6"
	
	tcp_options {
		destination_port_range {
			min = 80
			max = 443
		}
	}
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "Multiple port ranges with one including 22",
			Content: `
resource "oci_core_network_security_group_security_rule" "test" {
	direction = "INGRESS"
	source = "0.0.0.0/0"
	protocol = "6"
	
	tcp_options {
		destination_port_range {
			min = 80
			max = 443
		}
		
		destination_port_range {
			min = 20
			max = 25
		}
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCINetworkSecurityGroupSSHRule(),
					Message: "OCI Security Group rule 'oci_core_network_security_group_security_rule' allows unrestricted ingress access to port 22",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 64},
					},
				},
			},
		},
	}

	rule := NewOCINetworkSecurityGroupSSHRule()

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
