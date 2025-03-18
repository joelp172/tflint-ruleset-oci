package rules

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_OCIComputeInstanceMonitoring(t *testing.T) {
	cases := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "no agent_config block",
			Content: `
resource "oci_core_instance" "instance1" {
  availability_domain = "example-ad"
  compartment_id      = "ocid1.compartment.oc1..example"
  shape               = "VM.Standard2.1"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIComputeInstanceMonitoringRule(),
					Message: "OCI Compute Instance 'oci_core_instance' does not have monitoring enabled",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 41},
					},
				},
			},
		},
		{
			Name: "agent_config exists but is_monitoring_disabled not set",
			Content: `
resource "oci_core_instance" "instance2" {
  availability_domain = "example-ad"
  compartment_id      = "ocid1.compartment.oc1..example"
  shape               = "VM.Standard2.1"
  
  agent_config {
    is_management_disabled = false
  }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIComputeInstanceMonitoringRule(),
					Message: "OCI Compute Instance 'oci_core_instance' does not have monitoring enabled",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 41},
					},
				},
			},
		},
		{
			Name: "monitoring disabled",
			Content: `
resource "oci_core_instance" "instance3" {
  availability_domain = "example-ad"
  compartment_id      = "ocid1.compartment.oc1..example"
  shape               = "VM.Standard2.1"
  
  agent_config {
    is_monitoring_disabled = true
  }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIComputeInstanceMonitoringRule(),
					Message: "OCI Compute Instance 'oci_core_instance' does not have monitoring enabled",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 8, Column: 30},
						End:      hcl.Pos{Line: 8, Column: 34},
					},
				},
			},
		},
		{
			Name: "monitoring enabled",
			Content: `
resource "oci_core_instance" "instance4" {
  availability_domain = "example-ad"
  compartment_id      = "ocid1.compartment.oc1..example"
  shape               = "VM.Standard2.1"
  
  agent_config {
    is_monitoring_disabled = false
  }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "multiple instances with different configurations",
			Content: `
resource "oci_core_instance" "instance5" {
  availability_domain = "example-ad"
  compartment_id      = "ocid1.compartment.oc1..example"
  shape               = "VM.Standard2.1"
}

resource "oci_core_instance" "instance6" {
  availability_domain = "example-ad"
  compartment_id      = "ocid1.compartment.oc1..example"
  shape               = "VM.Standard2.1"
  
  agent_config {
    is_monitoring_disabled = false
  }
}

resource "oci_core_instance" "instance7" {
  availability_domain = "example-ad"
  compartment_id      = "ocid1.compartment.oc1..example"
  shape               = "VM.Standard2.1"
  
  agent_config {
    is_monitoring_disabled = true
  }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIComputeInstanceMonitoringRule(),
					Message: "OCI Compute Instance 'oci_core_instance' does not have monitoring enabled",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 41},
					},
				},
				{
					Rule:    NewOCIComputeInstanceMonitoringRule(),
					Message: "OCI Compute Instance 'oci_core_instance' does not have monitoring enabled",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 24, Column: 30},
						End:      hcl.Pos{Line: 24, Column: 34},
					},
				},
			},
		},
	}

	rule := NewOCIComputeInstanceMonitoringRule()

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