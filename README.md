# TFLint Ruleset for Oracle Cloud Infrastructure (OCI)
[![Build Status](https://github.com/joelp172/tflint-ruleset-oci/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/joelp172/tflint-ruleset-oci/actions)

TFLint ruleset plugin for Terraform OCI Provider

This ruleset focus on possible errors and best practices for OCI resources. Many rules are enabled by default and warn against code that might fail when running terraform apply, or clearly unrecommened.

## Requirements

- TFLint v0.42+
- Go v1.24

## Installation

You can install the plugin by adding a config to `.tflint.hcl` and running `tflint --init`:

```hcl
plugin "oci" {
    enabled = true
    version = "0.1.0"
    source  = "github.com/joelp172/tflint-ruleset-oci"
}
```

## Rules

See [Rules](docs/rules/README.md)

## Building the plugin

Clone the repository locally and run the following command:

```
$ make
```

You can easily install the built plugin with the following:

```
$ make install
```

You can run the built plugin like the following:

```
$ cat << EOS > .tflint.hcl
plugin "oci" {
  enabled = true
}
EOS
$ tflint
```
