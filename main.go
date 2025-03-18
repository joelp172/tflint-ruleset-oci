package main

import (
	"github.com/terraform-linters/tflint-plugin-sdk/plugin"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	"github.com/joelp172/tflint-ruleset-oci/rules"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		RuleSet: &tflint.BuiltinRuleSet{
			Name:    "oci",
			Version: "0.1.1",
			Rules: []tflint.Rule{
				rules.NewOCIComputeInstanceInTransitEncryptionRule(),
				rules.NewOCIComputeInstanceMonitoringRule(),
				rules.NewOCIObjectStorageBucketPublicAccessRule(),
				rules.NewOCIObjectStorageBucketVersioningRule(),
				rules.NewOCINetworkSecurityGroupSSHRule(),
				rules.NewOCIProviderHardcodedKeysRule(),
			},
		},
	})
}
