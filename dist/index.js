#!/usr/bin/env node


"use strict";
// See https://github.com/yargs/yargs/blob/master/docs/advanced.md#commanddirdirectory-opts for info on the structure of command modules

var _yargs = require("yargs");

var _yargs2 = _interopRequireDefault(_yargs);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

_yargs2.default.commandDir("yargs-cmds").demandCommand(1, `Please specify a commamd (see above for details and usage example)`).help("help").wrap(_yargs2.default.terminalWidth()).strict(true).completion("completion", "generate a bash/zsh(/etc.) command completion script. Run `gtm-cli completion >> ~/.bashrc && source ~/.bashrc` (for bash) or `gtm-cli completion >> ~/.zshrc && source ~/.zshrc` (for zsh) to enable it for the current user") // Add a pseudo command named "completion" which generates a bashrc compliant script to enabled CLI command completion for gtm-cli
.argv;

/*
    TODO:
    * yargs it up
    * add tests for existing fns
    * add flag for "only check valid/unexpired certs" (default: yes) - QS: &exclude=expired
    * think about arch and plan accordingly
    * allow for limiting scope to specific domain(s) (e.g. *.bbc.co.uk only) - e.g. --limit-scope=[bbc.co.uk,bbc.com]
    * could recurse onto discovered hostnames (need to set how many deep)
    * test types:
        * check orphaned zone delegations - got NS record but no result when `dig @<ns> any <hostname>`
        * check for cnames to 3rd party services
            * if s3, gcs etc. then check if service exists
            * check if dest domain is unregistered
            * check owner of domain, higher pri if not target org
        * check for a -> IPs not owned
            * make TLS connection to IP with servername and checkif hostname is on cert
            * poss check for keyword (brand name) in HTML - might be buggy esp on JS sites with no fallback
            * whois?
        * show each IP (A, AAAA, CNAME etc.) by AS
        * check server banners for typical services e.g. http, ftp, sftp, ssh - out of date versions CVEs
    * poss add option to use DNS recon to augment
    * add web crawler to pick up additional domains
    * add option to only output hostnames
    * add option to skip recon and just test list of hostnames
    * output should be ranked/grouped by severity
        * critical, high, medium, low, no risk
*/