"use strict";

var _subDomainScannerConfig = require("../../config/sub-domain-scanner-config.js");

var _subDomainScannerConfig2 = _interopRequireDefault(_subDomainScannerConfig);

var _querystring = require("querystring");

var _rssParser = require("rss-parser");

var _rssParser2 = _interopRequireDefault(_rssParser);

var _x509Parser = require("x509-parser");

var _x509Parser2 = _interopRequireDefault(_x509Parser);

var _os = require("os");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const { Resolver } = require("dns").promises; // NOTE: Path is relative to build dir (dist/)

const parser = new _rssParser2.default({
    customFields: {
        item: ["summary"]
    }
});

// Takes and array of hostnames, checks if they're orphaned DNS delegations (they have an NS record which is an NXDOMAIN), returns a boolean
async function isHostnameOrphanedDelegation(hostname) {
    if (!(typeof hostname === 'string')) {
        throw new TypeError("Value of argument \"hostname\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(hostname));
    }

    return new Promise(async (resolve, reject) => {
        try {
            const resolver = new Resolver();

            let nameservers = [];

            try {
                nameservers = await resolver.resolveNs(hostname);
            } catch (e) {
                if (e.code === "ENOTFOUND") {
                    return resolve(false);
                }
            }

            if (nameservers.length) {
                if (!(nameservers && (typeof nameservers[Symbol.iterator] === 'function' || Array.isArray(nameservers)))) {
                    throw new TypeError("Expected nameservers to be iterable, got " + _inspect(nameservers));
                }

                for (let nameserver of nameservers) {
                    let nameserverIP = "";

                    try // this requires a separate try/catch so that we can definitely determine that the NS DNS resolution fails
                    {
                        nameserverIP = await resolver.resolve4(nameserver);
                    } catch (e) // If we end up here, the NS IP didn't resolve, thus there's a potential vulnerability if the NS (esp. if the NS hostname is remote)
                    {
                        return resolve(true); // NOTE: this will happen for either NXDOMAIN on the NS destination
                    }

                    resolver.setServers(nameserverIP);

                    try {
                        const records = await resolver.resolveAny(hostname);

                        if (records.length) {
                            return resolve(false); // NOTE: This will happen if the NS exists but has no records for the hostname
                        }
                    } catch (e) {
                        if (e.code === "EREFUSED") {
                            return resolve(true); // ?
                        }
                    }
                }

                return resolve(true);
            }

            return resolve(false);
        } catch (e) {
            // Some DNS queries will error but are not a problem, we'll handle those here
            if (e.code === "ENODATA") // This happens when: hostname has no NS record
                {
                    resolve(false);
                } else if (e.code === "ENOTFOUND") // This happens when: hostname is NXDOMAIN
                {
                    resolve(false);
                }

            return reject(e);
        }
    });
}

// Takes an array of hostnames and filters them to remove out of scope entries
function filterHostnames(hostnames, mustMatch, mustNotMatch) {
    if (!Array.isArray(hostnames)) {
        throw new TypeError("Value of argument \"hostnames\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(hostnames));
    }

    if (!(mustMatch instanceof RegExp)) {
        throw new TypeError("Value of argument \"mustMatch\" violates contract.\n\nExpected:\nRegExp\n\nGot:\n" + _inspect(mustMatch));
    }

    if (!(mustNotMatch instanceof RegExp)) {
        throw new TypeError("Value of argument \"mustNotMatch\" violates contract.\n\nExpected:\nRegExp\n\nGot:\n" + _inspect(mustNotMatch));
    }

    const filteredHostnames = hostnames.filter(hostname => {
        if (hostname.match(mustMatch) && !hostname.match(mustNotMatch)) {
            return true;
        }

        return false;
    });

    return filteredHostnames;
}

// Takes an input arg of the RSS object "items" property and returns an Array of X509 certificates
function getCertificatesFromRSSItems(RSSItems) {
    if (!Array.isArray(RSSItems)) {
        throw new TypeError("Value of argument \"RSSItems\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(RSSItems));
    }

    const certificates = RSSItems.map(item => {
        try {
            const rawSummary = item.summary._;

            if (!(typeof rawSummary === 'string')) {
                throw new TypeError("Value of variable \"rawSummary\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(rawSummary));
            }

            const certificate = rawSummary.match(/-----BEGIN CERTIFICATE-----(.+)-----END CERTIFICATE-----/)[0].replace(/<br>/g, _os.EOL);

            if (!(typeof certificate === 'string')) {
                throw new TypeError("Value of variable \"certificate\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(certificate));
            }

            return certificate;
        } catch (e) {
            return undefined;
        }
    }).filter(cert => {
        return cert !== undefined;
    }); // Filter out any invalid certs

    if (!Array.isArray(certificates)) {
        throw new TypeError("Value of variable \"certificates\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(certificates));
    }

    return certificates;
}

// Takes an input of an Array of X509 certificates and returns a de-duped, sorted Array of SAN hostnames
function getSANSFromCertificatesArray(certificatesArray) {
    if (!Array.isArray(certificatesArray)) {
        throw new TypeError("Value of argument \"certificatesArray\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(certificatesArray));
    }

    let hostnamesSet = new Set();

    if (!(certificatesArray && (typeof certificatesArray[Symbol.iterator] === 'function' || Array.isArray(certificatesArray)))) {
        throw new TypeError("Expected certificatesArray to be iterable, got " + _inspect(certificatesArray));
    }

    for (let certificate of certificatesArray) // Note: we don't type-check certificate as it'll throw if we do and it's wrong
    {
        try {
            const SANS = _x509Parser2.default.getAltNames(certificate); // Array

            if (!Array.isArray(SANS)) {
                throw new TypeError("Value of variable \"SANS\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(SANS));
            }

            if (!(SANS && (typeof SANS[Symbol.iterator] === 'function' || Array.isArray(SANS)))) {
                throw new TypeError("Expected SANS to be iterable, got " + _inspect(SANS));
            }

            for (let hostname of SANS) {
                if (!(typeof hostname === 'string')) {
                    throw new TypeError("Value of variable \"hostname\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(hostname));
                }

                hostnamesSet.add(hostname.toLowerCase());
            }
        } catch (e) {
            // we don't need to do anything here(?), the certificate is wrongly formatted so we ignore it
        }
    }

    const rawHostnames = Array.from(hostnamesSet);

    if (!Array.isArray(rawHostnames)) {
        throw new TypeError("Value of variable \"rawHostnames\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(rawHostnames));
    }

    const hostnames = rawHostnames.sort();

    if (!Array.isArray(hostnames)) {
        throw new TypeError("Value of variable \"hostnames\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(hostnames));
    }

    return hostnames;
}

function getRSSURLFromHostname(hostname) {
    if (!(typeof hostname === 'string')) {
        throw new TypeError("Value of argument \"hostname\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(hostname));
    }

    const URLEncodedHostname = (0, _querystring.escape)(hostname.replace(/^\*/, "%"));
    const URL = `${_subDomainScannerConfig2.default.crtshRSSURLPrefix}${URLEncodedHostname}`;
    return URL;
}

async function getHostnamesFromCTLogs(hostname) {
    if (!(typeof hostname === 'string')) {
        throw new TypeError("Value of argument \"hostname\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(hostname));
    }

    return new Promise(async (resolve, reject) => {
        try {
            const RSSURL = getRSSURLFromHostname(hostname);
            const parsedRSS = await parser.parseURL(RSSURL);
            const certificates = getCertificatesFromRSSItems(parsedRSS.items);
            const SANS = getSANSFromCertificatesArray(certificates);
            return resolve(SANS);
        } catch (e) {
            return reject(e);
        }
    });
}

module.exports = {
    getCertificatesFromRSSItems: getCertificatesFromRSSItems,
    getSANSFromCertificatesArray: getSANSFromCertificatesArray,
    getRSSURLFromHostname: getRSSURLFromHostname,
    getHostnamesFromCTLogs: getHostnamesFromCTLogs,
    filterHostnames: filterHostnames,
    isHostnameOrphanedDelegation: isHostnameOrphanedDelegation
};

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