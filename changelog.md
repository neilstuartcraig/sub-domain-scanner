# sub-domain-scanner changelog

## v1.4.0
* Add `--bruteforce` option to `discover-hostnames`

## v1.3.0
* Add CLI method discover-domains
* Add auto wildcard output and dedupe output for discover-domains
* Dedupe output from discover-hostnames
* Add wildcard subsitution for common sub-domains for discover-hostnames output
* Minor fixes and tidies
* Try to fix Travis (this pkg requires node 11 currently)

## v1.2.0
* Add JSON output format for test-hostnames
* Output all hostnames in test-hostnames
* Fix cloudfront orphanage detection
* Other minor tidies and fixes

## v1.1.0
* Add yargs wrapper to support nice CI arguments
* Add hostname "must match" and "must not match" filtering and associated unit tests
* Add/improve tests
* Refactor

## v1.0.1
* Add some tests
* Add Travis integration
* Start on docs
* Amend license file to Apache 2

## v1.0.0
* Initial version
