"use strict";

var _os = require("os");

var _getStdin = require("get-stdin");

var _getStdin2 = _interopRequireDefault(_getStdin);

var _subDomainScannerLib = require("../lib/sub-domain-scanner-lib.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// NOTE: Path is relative to build dir (dist/) - local because lib is babel'd


const domainNamesOpt = {
    alias: ["domain-names", "domains", "dn"],
    demandOption: true,
    type: "array",
    description: "An Array of (strings) domain names to use as the seed. Example: --dn=hostname1,hostname 2"
};

const mustMatchOpt = {
    alias: ["must-match", "mm"],
    demandOption: false,
    type: "string",
    default: ".*",
    description: "A regular expression which hostnames must match to be included in the output"
};

const mustNotMatchOpt = {
    alias: ["must-not-match", "mnm"],
    demandOption: false,
    type: "string",
    default: "^$",
    description: "A regular expression which hostnames must not match to be included in the output"
};

const bruteforceOpt = {
    alias: ["bruteforce", "bf", "b"],
    demandOption: false,
    type: "boolean",
    default: false,
    description: "Whether (true) or not (false) to include a list of common sub-domain prefixes on each hostname"
};

let mod = {
    // Command name - i.e. sub-domain-scanner <command name> <options>
    command: "discover-hostnames",

    // Command description
    desc: "Discover hostnames from sources (CT logs, web pages - as per chosen options)",

    // Define command options
    builder: {
        domainNames: domainNamesOpt,
        mustMatch: mustMatchOpt,
        mustNotMatch: mustNotMatchOpt,
        bruteforce: bruteforceOpt
    },

    // Handler/main function - this is executed when this command is requested
    handler: async argv => {
        try {
            let allHostnames = new Set();

            let domainNames = [];

            if (argv.domainNames[0] === "-") // use stdin
                {
                    const stdin = await (0, _getStdin2.default)();
                    domainNames = stdin.trim().replace(/\ {2,}/g, " ").replace(/\ /g, ",").split(",");

                    if (!Array.isArray(domainNames)) {
                        throw new TypeError("Value of variable \"domainNames\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(domainNames));
                    }
                } else {
                domainNames = argv.domainNames;

                if (!Array.isArray(domainNames)) {
                    throw new TypeError("Value of variable \"domainNames\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(domainNames));
                }
            }

            if (!(domainNames && (typeof domainNames[Symbol.iterator] === 'function' || Array.isArray(domainNames)))) {
                throw new TypeError("Expected domainNames to be iterable, got " + _inspect(domainNames));
            }

            for (let domainName of domainNames) {
                const hostnames = await (0, _subDomainScannerLib.getHostnamesFromCTLogs)(domainName, argv.bruteforce);

                if (!Array.isArray(hostnames)) {
                    throw new TypeError("Value of variable \"hostnames\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(hostnames));
                }

                if (!(hostnames && (typeof hostnames[Symbol.iterator] === 'function' || Array.isArray(hostnames)))) {
                    throw new TypeError("Expected hostnames to be iterable, got " + _inspect(hostnames));
                }

                for (let hostname of hostnames) {
                    allHostnames.add(hostname);
                }
            }

            const mustMatch = new RegExp(argv.mustMatch);
            const mustNotMatch = new RegExp(argv.mustNotMatch);

            const dedupedHostnames = Array.from(allHostnames);
            const filteredHostnames = (0, _subDomainScannerLib.filterHostnames)(dedupedHostnames, mustMatch, mustNotMatch);
            const output = filteredHostnames.join(_os.EOL);

            console.log(output);
            process.exit(0);
        } catch (e) {
            console.error(e.message);
            process.exit(1);
        }
    }
};

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