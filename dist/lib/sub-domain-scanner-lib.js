"use strict";

var _subDomainScannerConfig = require("../../config/sub-domain-scanner-config.js");

var _subDomainScannerConfig2 = _interopRequireDefault(_subDomainScannerConfig);

var _assert = require("assert");

var _assert2 = _interopRequireDefault(_assert);

var _querystring = require("querystring");

var _rssParser = require("rss-parser");

var _rssParser2 = _interopRequireDefault(_rssParser);

var _x509Parser = require("x509-parser");

var _x509Parser2 = _interopRequireDefault(_x509Parser);

var _path = require("path");

var _os = require("os");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// NOTE: Path is relative to build dir (dist/)

const { Resolver } = require("dns").promises;

const fsp = require("fs").promises;


const parser = new _rssParser2.default({
    customFields: {
        item: ["summary"]
    }
});

/*

TODO: Connvert the output of isHostnameOrphanedDelegation() to an obj:
{
    isOrphanedDelegation: Boolean,
    risk: [low|medium|high] (low: orphaned but points to own infra, med: oprhaned but ??, high: orphaned and points to e.g. R53/GDNS etc.)
}

newshub-live-mosdatastore.newsonline.tc.nca.bbc.co.uk is a SERVFAIL and flags as vulnerable but since it doesn't exist, it isn't
    // might need to initially check if we get ESERVFAIL

*/

async function readFileContentsIntoArray(filename, separator = _os.EOL, fileEncoding = "utf8", outputCharset = "utf8") {
    if (!(typeof filename === 'string')) {
        throw new TypeError("Value of argument \"filename\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(filename));
    }

    if (!(typeof separator === 'string')) {
        throw new TypeError("Value of argument \"separator\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(separator));
    }

    if (!(typeof fileEncoding === 'string')) {
        throw new TypeError("Value of argument \"fileEncoding\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(fileEncoding));
    }

    if (!(typeof outputCharset === 'string')) {
        throw new TypeError("Value of argument \"outputCharset\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(outputCharset));
    }

    return new Promise(async (resolve, reject) => {
        try {
            const filenameAndPath = (0, _path.resolve)(filename);

            if (!(typeof filenameAndPath === 'string')) {
                throw new TypeError("Value of variable \"filenameAndPath\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(filenameAndPath));
            }

            const fileContent = await fsp.readFile(filenameAndPath, fileEncoding);

            if (!(typeof fileContent === 'string')) {
                throw new TypeError("Value of variable \"fileContent\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(fileContent));
            }

            const output = fileContent.trim().split(separator).filter(val => {
                return val.length; // Filter out empty values
            });

            if (!Array.isArray(output)) {
                throw new TypeError("Value of variable \"output\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(output));
            }

            return resolve(output);
        } catch (e) {
            reject(e);
        }
    });
}

// Takes and array of hostnames, checks if they're orphaned DNS delegations (they have an NS record which is an NXDOMAIN), returns a boolean
async function isHostnameOrphanedDelegation(hostname) {
    if (!(typeof hostname === 'string')) {
        throw new TypeError("Value of argument \"hostname\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(hostname));
    }

    return new Promise(async (resolve, reject) => {
        try {
            const mainResolver = new Resolver();
            const NSResolver = new Resolver();

            let nameservers = [];
            let resolverSOA = {};

            // Check if the hostname _is_ delegated, exit early if not
            try {
                nameservers = await mainResolver.resolveNs(hostname);
                resolverSOA = await mainResolver.resolveSoa(hostname);
            } catch (e) {
                if (e.code === "ENOTFOUND") // hostname is not delegated (there are no NSs or no SOA)
                    {
                        // TODO: #NSIsAnIP                   
                        // need a check here to see if the NS is an IP address as those records will fail resolveNs() with ENOTFOUND
                        // unsure how best to tackle this though, doesn't seem to be doable in node :-(

                        return resolve(false);
                    } else if (e.code === "ESERVFAIL") // This happens on an orphaned hostname e.g. ns-not-exists-local.thedotproduct.org which has non-existant NS destinations
                    {
                        console.log("SF");
                        // is this always an orphaned sub-domain?
                        return resolve(true);
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
                        // We'll directly query the nameserver below, for which we need the IP as setServers doesn't accept a hostname
                        // At some point, we'll need to also/instead use IPv6 resolution, but I CBA right now
                        nameserverIP = await mainResolver.resolve4(nameserver);
                        NSResolver.setServers(nameserverIP);

                        try {
                            const nameserverSOA = await NSResolver.resolveSoa(hostname);

                            if (_assert2.default.deepStrictEqual(resolverSOA, nameserverSOA) === false) {
                                return resolve(true);
                            }
                        } catch (e) {
                            if (e.code === "ENOTFOUND") {
                                return resolve(true);
                            }
                        }
                    } catch (e) // If we end up here, the NS IP didn't resolve, which could be a takeover vulnerability (if someone else owns the IP)
                    {
                        return resolve(true);
                    }
                }
            }

            return resolve(false);
        } catch (e) {
            // Some DNS queries will error but are not a problem, we'll handle those here
            if (e.code === "ENODATA") // This happens when: hostname has no NS record
                {
                    return resolve(false);
                } else if (e.code === "ENOTFOUND") // This happens when: hostname is NXDOMAIN
                {
                    return resolve(false);
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
    isHostnameOrphanedDelegation: isHostnameOrphanedDelegation,
    readFileContentsIntoArray: readFileContentsIntoArray
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