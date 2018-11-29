"use strict";

var _axios = require("axios");

var _getStdin = require("get-stdin");

var _getStdin2 = _interopRequireDefault(_getStdin);

var _subDomainScannerLib = require("../lib/sub-domain-scanner-lib.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

const nameserversOpt = {
    alias: ["nameservers", "ns"],
    demandOption: true,
    type: "array",
    description: "An array (of space-separated strings) of nameservers to discover hostnames under. Example: --ns=ns1.example.com ns2.example.com or using stdin: --ns=-"
};

let mod = {
    // Command name - i.e. sub-domain-scanner <command name> <options>
    command: "discover-domains",

    // Command description
    desc: "Discover domain names CLI method (via nameservers)",

    // Define command options
    builder: {
        nameservers: nameserversOpt
    },

    // Handler/main function - this is executed when this command is requested
    handler: async argv => {
        try {
            let nameservers = [];

            if (argv.hostnamesFile === "-") // use stdin
                {
                    nameservers = await (0, _getStdin2.default)();

                    if (!Array.isArray(nameservers)) {
                        throw new TypeError("Value of variable \"nameservers\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(nameservers));
                    }
                } else {
                nameservers = argv.nameservers;

                if (!Array.isArray(nameservers)) {
                    throw new TypeError("Value of variable \"nameservers\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(nameservers));
                }
            }

            let domainsSet = new Set();

            if (!(nameservers && (typeof nameservers[Symbol.iterator] === 'function' || Array.isArray(nameservers)))) {
                throw new TypeError("Expected nameservers to be iterable, got " + _inspect(nameservers));
            }

            for (let nameserver of nameservers) {
                const domainsTmp = await (0, _subDomainScannerLib.getDomainNamesFromNameserver)(nameserver, _axios.get);

                if (!Array.isArray(domainsTmp)) {
                    throw new TypeError("Value of variable \"domainsTmp\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(domainsTmp));
                }

                if (!(domainsTmp && (typeof domainsTmp[Symbol.iterator] === 'function' || Array.isArray(domainsTmp)))) {
                    throw new TypeError("Expected domainsTmp to be iterable, got " + _inspect(domainsTmp));
                }

                for (let rawDomain of domainsTmp) {
                    // NOTE: Due to using the RSS interface (rather than PGSQL), have example.com _and_ *.example.com _does_ make a difference, hence:
                    // TODO: consider adding more common sub-domains here (from config ideally)                    
                    domainsSet.add(`${rawDomain}`);
                    domainsSet.add(`*.${rawDomain}`);
                }
            }

            const domainsString = Array.from(domainsSet).join(",");

            if (!(typeof domainsString === 'string')) {
                throw new TypeError("Value of variable \"domainsString\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(domainsString));
            }

            console.log(domainsString);
            process.exit();
        } catch (e) {
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