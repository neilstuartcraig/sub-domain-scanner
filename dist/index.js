"use strict";

// TODO: have a specific var for the lib filename and use that for consistency
// import {default as config} from "../config/sub-domain-scanner-config.js"; // NOTE: Path is relative to build dir (dist/)

var _subDomainScannerLib = require("./lib/sub-domain-scanner-lib.js");

// NOTE: Path is relative to build dir (dist/) - local because lib is babel'd


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

async function main() {
    // NOTE: this won't actually be the fn that gets called, it'll be e.g. run(<opts>)
    const CTLogs = await (0, _subDomainScannerLib.getHostnamesFromCTLogs)("www.thedotproduct.org");

    if (!(CTLogs && (typeof CTLogs[Symbol.iterator] === 'function' || Array.isArray(CTLogs)))) {
        throw new TypeError("Expected CTLogs to be iterable, got " + _inspect(CTLogs));
    }

    for (let hostname of CTLogs) {
        console.log(`${hostname}`);
    }

    console.log(`Found ${CTLogs.length} hostnames`);
}

main();

function _inspect(input, depth) {
    const maxDepth = 4;
    const maxKeys = 15;

    if (depth === undefined) {
        depth = 0;
    }

    depth += 1;

    if (input === null) {
        return 'null';
    } else if (input === undefined) {
        return 'void';
    } else if (typeof input === 'string' || typeof input === 'number' || typeof input === 'boolean') {
        return typeof input;
    } else if (Array.isArray(input)) {
        if (input.length > 0) {
            if (depth > maxDepth) return '[...]';

            const first = _inspect(input[0], depth);

            if (input.every(item => _inspect(item, depth) === first)) {
                return first.trim() + '[]';
            } else {
                return '[' + input.slice(0, maxKeys).map(item => _inspect(item, depth)).join(', ') + (input.length >= maxKeys ? ', ...' : '') + ']';
            }
        } else {
            return 'Array';
        }
    } else {
        const keys = Object.keys(input);

        if (!keys.length) {
            if (input.constructor && input.constructor.name && input.constructor.name !== 'Object') {
                return input.constructor.name;
            } else {
                return 'Object';
            }
        }

        if (depth > maxDepth) return '{...}';
        const indent = '  '.repeat(depth - 1);
        let entries = keys.slice(0, maxKeys).map(key => {
            return (/^([A-Z_$][A-Z0-9_$]*)$/i.test(key) ? key : JSON.stringify(key)) + ': ' + _inspect(input[key], depth) + ';';
        }).join('\n  ' + indent);

        if (keys.length >= maxKeys) {
            entries += '\n  ' + indent + '...';
        }

        if (input.constructor && input.constructor.name && input.constructor.name !== 'Object') {
            return input.constructor.name + ' {\n  ' + indent + entries + '\n' + indent + '}';
        } else {
            return '{\n  ' + indent + entries + '\n' + indent + '}';
        }
    }
}