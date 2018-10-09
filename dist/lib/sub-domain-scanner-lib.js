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

// NOTE: Path is relative to build dir (dist/)

const parser = new _rssParser2.default({
    customFields: {
        item: ["summary"]
    }
});

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

    for (let certificate of certificatesArray) {
        if (!(typeof certificate === 'string')) {
            throw new TypeError("Value of variable \"certificate\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(certificate));
        }

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
    getHostnamesFromCTLogs: getHostnamesFromCTLogs
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