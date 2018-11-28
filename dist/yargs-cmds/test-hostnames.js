"use strict";

var _os = require("os");

var _getStdin = require("get-stdin");

var _getStdin2 = _interopRequireDefault(_getStdin);

var _axios = require("axios");

var _subDomainScannerLib = require("../lib/sub-domain-scanner-lib.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const { Resolver } = require("dns").promises;
// NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

const hostnamesFileOpt = {
    alias: ["hostnames-file", "hosts-file", "hf", "f"],
    demandOption: true,
    type: "string",
    description: "A filename which contains hostnames to test (one file per line). usage: --hostnames-file /path/to/file or --hostnames-file - (to use stdin)"
};

let mod = {
    // Command name - i.e. gtm-cli <command name> <options>
    command: "test-hostnames",

    // Command description
    desc: "Test hostnames for takeover vulnerabilities",

    // Define command options
    builder: {
        hostnamesFile: hostnamesFileOpt
    },

    // Handler/main function - this is executed when this command is requested
    handler: async argv => {
        try {
            // read/handle file/stdin
            // iterate through each hostname
            // check if sub-domain has NS
            //  y: check if orphaned delegation (e.g. dig ns <domain> and check for records then for each NS, dig@<NS> an <domain> and check for NXDOMAIN)
            // check if CNAME to 3rd party host and !configured (S3 etc), medium: missing all entries in array of strings (arg) (i.e. pointing to outdated dest) - could maybe do via a scoring system. could check if has TLS cert not owned by main site owner but that should show in CT
            let hostnames = [];

            if (argv.hostnamesFile === "-") // use stdin
                {
                    const stdin = await (0, _getStdin2.default)();

                    if (!(typeof stdin === 'string')) {
                        throw new TypeError("Value of variable \"stdin\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(stdin));
                    }

                    if (stdin.length) {
                        const re = new RegExp(_os.EOL, "g");
                        hostnames = stdin.trim().replace(re, " ").split(" "); // We have to replace newlines with space because the output from discover-hostnames is newline-separated      

                        if (!Array.isArray(hostnames)) {
                            throw new TypeError("Value of variable \"hostnames\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(hostnames));
                        }
                    } else {
                        console.error("Please supply a space-separated list of hostnames to test");
                        process.exit(1);
                    }
                } else // use file
                {
                    try {
                        // read file in from disk + make an array
                        hostnames = await (0, _subDomainScannerLib.readFileContentsIntoArray)(argv.hostnamesFile);

                        if (!Array.isArray(hostnames)) {
                            throw new TypeError("Value of variable \"hostnames\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(hostnames));
                        }
                    } catch (e) {
                        // TODO: Handle errors in a more friendly way
                        console.error(e);
                        process.exit(1);
                    }
                }

            let vulnerabilities = {};

            if (!(hostnames && (typeof hostnames[Symbol.iterator] === 'function' || Array.isArray(hostnames)))) {
                throw new TypeError("Expected hostnames to be iterable, got " + _inspect(hostnames));
            }

            for (let hostname of hostnames) {
                // We'll create an empty array in the vulnerabilities object which could be helpful in the output to know a hostname has been tested
                vulnerabilities[hostname] = [];

                const isVulnerableDelegation = await (0, _subDomainScannerLib.isHostnameOrphanedDelegation)(hostname, Resolver, _axios.get);
                if (isVulnerableDelegation.vulnerable) {
                    vulnerabilities[hostname].push(isVulnerableDelegation);
                }

                // TODO: in discover, add https://hackertarget.com/find-shared-dns-servers/ - seems to find a lot of related domains - try search for ns4.bbc.co.uk

                // test whether orphaned here
                const isOrphaned = await (0, _subDomainScannerLib.isHostnameOrphaned)(hostname, Resolver, _axios.get); // TODO: rename isOrphaned

                if (!(isOrphaned instanceof Object)) {
                    throw new TypeError("Value of variable \"isOrphaned\" violates contract.\n\nExpected:\nObject\n\nGot:\n" + _inspect(isOrphaned));
                }

                if (isOrphaned.vulnerable) {
                    vulnerabilities[hostname].push(isOrphaned);
                }

                // TODO: auto takeover for s3 etc. - do as another cmd e.g. sub-domain-scanner auto-takover <hostname> <vuln type>

                // TODO: more checks
                //
            }

            // TODO YAML output format
            console.log(JSON.stringify(vulnerabilities, null, 2));
            process.exit(0);
        } catch (e) {
            console.log("throwing here - test-hostname. need to find in lib");
            console.error(e.message);
            process.exit(1);
        }
    }
};

// exports.default = mod;
module.exports = mod;

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