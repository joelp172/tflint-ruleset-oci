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

  signing_key = <<-KEY
  -----BEGIN PGP PUBLIC KEY BLOCK-----
  mDMEZ9lWDBYJKwYBBAHaRw8BAQdAzEHbV23E2TSQCqRU66OTevnXypPyk1cIdq2I
  Rx6ki8e0KEpvZWwgUGluZGVyIDxqb2VsLnBpbmRlckBwcm90b25tYWlsLmNvbT6I
  kwQTFgoAOxYhBJNOC76sc5HN/kHD+L3SQmX0bRPgBQJn2VYMAhsDBQsJCAcCAiIC
  BhUKCQgLAgQWAgMBAh4HAheAAAoJEL3SQmX0bRPgTFsBAO8hGsLsrK4rLDlCnUwt
  XfimtveFJQWSMUGZhbhp6mdLAP9I7suPIjgqZ11SMOYgLqbnJh4v1ljyUXMOkq7B
  hWDIArg4BGfZVgwSCisGAQQBl1UBBQEBB0BkwQ92oLAIXM//1zF+/vaRKPC6ZZBI
  7o7WAIcqN1iyLwMBCAeIeAQYFgoAIBYhBJNOC76sc5HN/kHD+L3SQmX0bRPgBQJn
  2VYMAhsMAAoJEL3SQmX0bRPg0eoBANoOcO6cggFrsR/dmBHvKl87R9FeMoUybn95
  9U3mQXOmAQCRsREiV4yzLsR2oCTQJyJ5d/hRsya5mKB77yJt3bk8AA==
  =PqA9
  -----END PGP PUBLIC KEY BLOCK-----
  KEY
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
