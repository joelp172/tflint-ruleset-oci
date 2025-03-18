package rules

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_OCIComputeInstanceInTransitEncryptionValidation(t *testing.T) {
	cases := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "no launch_options block",
			Content: `
resource "oci_core_instance" "instance" {
  availability_domain = "ad1"
  compartment_id      = "ocid1.compartment.oc1..unique_id"
  shape               = "VM.Standard2.1"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIComputeInstanceInTransitEncryptionRule(),
					Message: "OCI Compute Instance boot volume does not have in-transit data encryption enabled",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 40},
					},
				},
			},
		},
		{
			Name: "missing is_pv_encryption_in_transit_enabled attribute",
			Content: `
resource "oci_core_instance" "instance" {
  availability_domain = "ad1"
  compartment_id      = "ocid1.compartment.oc1..unique_id"
  shape               = "VM.Standard2.1"
  
  launch_options {
    network_type = "VFIO"
  }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIComputeInstanceInTransitEncryptionRule(),
					Message: "OCI Compute Instance 'oci_core_instance' does not have boot volume in-transit data encryption enabled",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 40},
					},
				},
			},
		},
		{
			Name: "is_pv_encryption_in_transit_enabled is false",
			Content: `
resource "oci_core_instance" "instance" {
  availability_domain = "ad1"
  compartment_id      = "ocid1.compartment.oc1..unique_id"
  shape               = "VM.Standard2.1"
  
  launch_options {
    is_pv_encryption_in_transit_enabled = false
  }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIComputeInstanceInTransitEncryptionRule(),
					Message: "OCI Compute Instance 'oci_core_instance' does not have boot volume in-transit data encryption enabled",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 8, Column: 43},
						End:      hcl.Pos{Line: 8, Column: 48},
					},
				},
			},
		},
		{
			Name: "is_pv_encryption_in_transit_enabled is true",
			Content: `
resource "oci_core_instance" "instance" {
  availability_domain = "ad1"
  compartment_id      = "ocid1.compartment.oc1..unique_id"
  shape               = "VM.Standard2.1"
  
  launch_options {
    is_pv_encryption_in_transit_enabled = true
  }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "multiple instances with different configurations",
			Content: `
resource "oci_core_instance" "compliant_instance" {
  availability_domain = "ad1"
  compartment_id      = "ocid1.compartment.oc1..unique_id"
  shape               = "VM.Standard2.1"
  
  launch_options {
    is_pv_encryption_in_transit_enabled = true
  }
}

resource "oci_core_instance" "non_compliant_instance" {
  availability_domain = "ad1"
  compartment_id      = "ocid1.compartment.oc1..unique_id"
  shape               = "VM.Standard2.1"
  
  launch_options {
    is_pv_encryption_in_transit_enabled = false
  }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewOCIComputeInstanceInTransitEncryptionRule(),
					Message: "OCI Compute Instance 'oci_core_instance' does not have boot volume in-transit data encryption enabled",
					Range: hcl.Range{
						Filename: "main.tf",
						Start:    hcl.Pos{Line: 18, Column: 43},
						End:      hcl.Pos{Line: 18, Column: 48},
					},
				},
			},
		},
	}

	rule := NewOCIComputeInstanceInTransitEncryptionRule()

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
