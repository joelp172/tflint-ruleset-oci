package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// OCIProviderHardcodedKeysRule checks if OCI private keys are hard coded in the provider
type OCIProviderHardcodedKeysRule struct {
	tflint.DefaultRule
}

// NewOCIProviderHardcodedKeysRule returns a new rule
func NewOCIProviderHardcodedKeysRule() *OCIProviderHardcodedKeysRule {
	return &OCIProviderHardcodedKeysRule{}
}

// Name returns the rule name
func (r *OCIProviderHardcodedKeysRule) Name() string {
	return "oci_provider_hardcoded_keys"
}

// Enabled returns whether the rule is enabled by default
func (r *OCIProviderHardcodedKeysRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *OCIProviderHardcodedKeysRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *OCIProviderHardcodedKeysRule) Link() string {
	return "https://docs.oracle.com/en-us/iaas/Content/Security/Reference/iam_security.htm"
}

// Check checks if OCI private keys are hard coded in the provider
func (r *OCIProviderHardcodedKeysRule) Check(runner tflint.Runner) error {
	providers, err := runner.GetProviderContent("oci", &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "private_key_password"},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, provider := range providers.Blocks {
		passwordAttr, exists := provider.Body.Attributes["private_key_password"]
		if !exists {
			continue
		}

		var password string
		err = runner.EvaluateExpr(passwordAttr.Expr, &password, nil)
		if err != nil {
			return err
		}
		
		isVar := len(passwordAttr.Expr.Variables()) > 0

		// If it's a literal value (not a variable or function), it's hardcoded
		if !isVar {
			runner.EmitIssue(
				r,
				"OCI provider has hard-coded private key password",
				passwordAttr.Expr.Range(),
			)
		}
	}
	return nil
}