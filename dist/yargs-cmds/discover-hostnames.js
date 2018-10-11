"use strict";

var _os = require("os");

var _subDomainScannerLib = require("../lib/sub-domain-scanner-lib.js");

// NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

// // import necessary yargs options
// import {GTMEnvironment, productEnvironment, GTMEdgeRegion, HTTPSProxy} from "../lib/functions/yargs-options.js";

const domainNamesOpt = {
    alias: ["domain-names", "domains", "dn"],
    demandOption: true,
    type: "array",
    description: "An Array of (strings) domain names to use as the seed. usage: --dn hostname1 hostname 2"
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

/*
args to add:
    --include-ct-logs boolean (true)
    --ignore-expired-certs boolean (false)

    --include-web-crawl boolean (true)
    --web-crawl-depth int (1)
*/

let mod = {
    // Command name - i.e. gtm-cli <command name> <options>
    command: "discover-hostnames",

    // Command description
    desc: "Discover hostnames from sources (CT logs, web pages - as per chosen options)",

    // Define command options
    builder: {
        domainNames: domainNamesOpt,
        mustMatch: mustMatchOpt,
        mustNotMatch: mustNotMatchOpt
    },

    // Handler/main function - this is executed when this command is requested
    handler: async argv => {
        try {
            let allHostnames = [];

            _argv$domainNames = argv.domainNames;

            if (!(_argv$domainNames && (typeof _argv$domainNames[Symbol.iterator] === 'function' || Array.isArray(_argv$domainNames)))) {
                throw new TypeError("Expected _argv$domainNames to be iterable, got " + _inspect(_argv$domainNames));
            }

            for (let hostname of _argv$domainNames) {
                var _argv$domainNames;

                const hostnames = await (0, _subDomainScannerLib.getHostnamesFromCTLogs)(hostname);
                allHostnames = allHostnames.concat(hostnames);
            }

            const mustMatch = new RegExp(argv.mustMatch);
            const mustNotMatch = new RegExp(argv.mustNotMatch);

            const filteredHostnames = (0, _subDomainScannerLib.filterHostnames)(allHostnames, mustMatch, mustNotMatch);
            const output = filteredHostnames.join(_os.EOL);

            console.log(output);
            process.exit(0);
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