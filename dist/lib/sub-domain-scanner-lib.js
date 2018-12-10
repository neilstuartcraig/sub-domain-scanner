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

var _ipRangeCheck = require("ip-range-check");

var _ipRangeCheck2 = _interopRequireDefault(_ipRangeCheck);

var _path = require("path");

var _os = require("os");

var _net = require("net");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// NOTE: Path is relative to build dir (dist/)

const fsp = require("fs").promises;


const parser = new _rssParser2.default({
    customFields: {
        item: ["summary"]
    }
});

// TODO: mnove this to config or somewhere more sensible
// NOTE: This borrows and is inspired by https://github.com/EdOverflow/smith/blob/master/smith
const thirdPartyServicesChecks = [{
    "name": "AWS S3 bucket",
    "hostnameRegex": /s3\-.+\.amazonaws\.com$/i,
    "scheme": "https",
    "responseStatusForNonExisting": 404,
    "responseBodyMatchForNonExisting": "NoSuchBucket"
}, {
    "name": "Google Cloud Storage bucket",
    "hostnameRegex": /^c\.storage\.googleapis\.com$/i,
    "scheme": "https",
    "responseStatusForNonExisting": 404,
    "responseBodyMatchForNonExisting": "InvalidBucketName"
}, {
    "name": "Cloudfront distribution",
    "hostnameRegex": /.+\.cloudfront\.net$/i,
    "scheme": "https",
    "responseStatusForNonExisting": 404,
    "responseBodyMatchForNonExisting": "The request could not be satisfied"
}, {
    "name": "Fastly configuration",
    "hostnameRegex": /.+\.fastly\.net$/i,
    "scheme": "http",
    "responseStatusForNonExisting": null,
    "responseBodyMatchForNonExisting": "Fastly error: unknown domain"
}, {
    "name": "github.io account",
    "hostnameRegex": /.+\.github\.io$/i,
    "scheme": "https",
    "responseStatusForNonExisting": 404,
    "responseBodyMatchForNonExisting": "There isn't a GitHub Pages site here."
}, {
    "name": "Zendesk account",
    "hostnameRegex": /.+\.zendesk\.com$/i,
    "scheme": "http",
    "responseStatusForNonExisting": 200, // NOTE: This is the result of a 301
    "responseBodyMatchForNonExisting": "Bummer. It looks like the help center that you are trying to reach no longer exists."
}, {
    "name": "Wordpress.com hosting account",
    "hostnameRegex": /.+\.wordpress\.com$/i,
    "scheme": "https",
    "responseStatusForNonExisting": 200,
    "responseBodyMatchForNonExisting": /.+wordpress\.com\<\/em> doesn&#8217;t&nbsp;exist/g
}, {
    "name": "Heroku app",
    "hostnameRegex": /.+herokuapp\.com$/i,
    "scheme": "http",
    "responseStatusForNonExisting": 404,
    "responseBodyMatchForNonExisting": "<iframe src=\"//www.herokucdn.com/error-pages/no-such-app.html\"></iframe>"
    // TODO: Add more!
}];

// TODO: move this to a config file
// Shamelessly stolen (and truncated, top N) from https://raw.githubusercontent.com/darkoperator/dnsrecon/master/subdomains-top1mil.txt for a starter
const subDomainPrefixes = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "webdisk", "pop", "cpanel", "whm", "ns1", "ns2", "autodiscover", "autoconfig", "ns", "test", "m", "blog", "dev", "www2", "ns3", "pop3", "forum", "admin", "mail2", "vpn", "mx", "imap", "old", "new", "mobile", "mysql", "beta", "support", "cp", "secure", "shop", "demo", "dns2", "ns4", "dns1", "static", "lists", "web", "www1", "img", "news", "portal", "server", "wiki", "api", "media", "images", "www.blog", "backup", "dns", "sql", "intranet", "www.forum", "www.test", "stats", "host", "video", "mail1", "mx1", "www3", "staging", "www.m", "sip", "chat", "search", "crm", "mx2", "ads", "ipv4", "remote", "email", "my", "wap", "svn", "store", "cms", "download", "proxy", "www.dev", "mssql", "apps", "dns3", "exchange", "mail3", "forums", "ns5", "db", "office", "live", "files", "info", "owa", "monitor", "helpdesk", "panel", "sms", "newsletter", "ftp2", "web1", "web2", "upload", "home", "bbs", "login", "app", "en", "blogs", "it", "cdn", "stage", "gw", "dns4", "www.demo", "ssl"];

const axiosGetConfig = {
    validateStatus: () => {
        return true;
    }
};

async function getDomainNamesFromNameserver(nameserver, axiosGetFn) {
    if (!(typeof nameserver === 'string')) {
        throw new TypeError("Value of argument \"nameserver\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(nameserver));
    }

    if (!(typeof axiosGetFn === 'function')) {
        throw new TypeError("Value of argument \"axiosGetFn\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(axiosGetFn));
    }

    return new Promise(async (resolve, reject) => {
        try {
            // TODO: better filtering to avoid security issues with nameserver var content
            const serviceURL = `https://api.hackertarget.com/findshareddns/?q=${nameserver}`;
            const response = await axiosGetFn(serviceURL, axiosGetConfig);

            // A request for a non-existing NS results in a 200 so we have to put in a brittle special case...

            if (!(response instanceof Object)) {
                throw new TypeError("Value of variable \"response\" violates contract.\n\nExpected:\nObject\n\nGot:\n" + _inspect(response));
            }

            if (response.data === "error check your search parameter") {
                // ...but we don't want to error, just return nowt (i think)
                return resolve([]);
            }

            const domains = response.data.trim().split(_os.EOL);

            if (!Array.isArray(domains)) {
                throw new TypeError("Value of variable \"domains\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(domains));
            }

            return resolve(domains);
        } catch (e) {
            return reject(e);
        }
    });
}

// TODO: ignore hostnames which are wildcarded e.g. *.api.bbc.co.uk 


// Takes a DNS recordset and tests whether it is a CNAME to a 3rd party storage service e.g. AWS S3
async function isHostnameCNameTo3rdParty(hostname, cnames, axiosGetFn) {
    if (!(typeof hostname === 'string')) {
        throw new TypeError("Value of argument \"hostname\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(hostname));
    }

    if (!Array.isArray(cnames)) {
        throw new TypeError("Value of argument \"cnames\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(cnames));
    }

    if (!(typeof axiosGetFn === 'function')) {
        throw new TypeError("Value of argument \"axiosGetFn\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(axiosGetFn));
    }

    let output = {
        "vulnerable": false,
        "reasonCode": "",
        "reason": "",
        "severity": ""
    };

    if (!(cnames && (typeof cnames[Symbol.iterator] === 'function' || Array.isArray(cnames)))) {
        throw new TypeError("Expected cnames to be iterable, got " + _inspect(cnames));
    }

    for (let cname of cnames) {
        if (!(thirdPartyServicesChecks && (typeof thirdPartyServicesChecks[Symbol.iterator] === 'function' || Array.isArray(thirdPartyServicesChecks)))) {
            throw new TypeError("Expected thirdPartyServicesChecks to be iterable, got " + _inspect(thirdPartyServicesChecks));
        }

        for (let thirdPartyServiceCheckConfig of thirdPartyServicesChecks) {
            if (cname.match(thirdPartyServiceCheckConfig.hostnameRegex)) {
                try {
                    const serviceURL = `${thirdPartyServiceCheckConfig.scheme}://${cname}/`;
                    const response = await axiosGetFn(serviceURL, axiosGetConfig);

                    if (response.data.match(thirdPartyServiceCheckConfig.responseBodyMatchForNonExisting) && response.status === thirdPartyServiceCheckConfig.responseStatusForNonExisting) {
                        output.vulnerable = true;
                        output.reason = `${hostname} is a CNAME to ${cname} (unconfigured ${thirdPartyServiceCheckConfig.name})`;
                        output.reasonCode = `CNAMED_TO_UNCONFIGURED_3RD_PARTY_SVC`;
                        output.severity = "high";
                        break; // Presumably, it's not possible for a single cname to be directed at >1 storage service (?)
                    }
                } catch (e) {
                    if (e.code === "ENOTFOUND") {
                        output.vulnerable = true;
                        output.reason = `${hostname} is a CNAME to ${cname} (non-existant DNS for ${thirdPartyServiceCheckConfig.name})`;
                        output.reasonCode = `CNAMED_TO_NON_EXIST_DNS_3RD_PARTY_SVC`;
                        output.severity = "medium"; // is this actually medium?
                        break; // Presumably, it's not possible for a single cname to be directed at >1 storage service (?)
                    }
                    // ... more?
                }
            }
        }
    }

    return output;
}

// Takes a hostname and tests whether it is orphaned (e.g. a cname pointing to a non-existant AWS S3 bucket)
async function isHostnameOrphaned(hostname, Resolver, axiosGetFn) // TODO: consider adding an object arg containing "safe" destinations
{
    if (!(typeof hostname === 'string')) {
        throw new TypeError("Value of argument \"hostname\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(hostname));
    }

    if (!(Resolver instanceof Object)) {
        throw new TypeError("Value of argument \"Resolver\" violates contract.\n\nExpected:\nObject\n\nGot:\n" + _inspect(Resolver));
    }

    if (!(typeof axiosGetFn === 'function')) {
        throw new TypeError("Value of argument \"axiosGetFn\" violates contract.\n\nExpected:\nFunction\n\nGot:\n" + _inspect(axiosGetFn));
    }

    return new Promise(async (resolve, reject) => {
        try {
            // Check for 
            // cname to 3rd party e.g. S3/GCS/CDN
            // see https://github.com/EdOverflow/smith/blob/master/smith
            // See https://github.com/EdOverflow/can-i-take-over-xyz
            // A -> 3rd party IP (v4/v6)

            const resolver = new Resolver();
            const cnames = await resolver.resolveCname(hostname);

            const isCNamedTo3rdParty = isHostnameCNameTo3rdParty(hostname, cnames, axiosGetFn);

            return resolve(isCNamedTo3rdParty);
        } catch (e) {
            if (e.code === "ENODATA" || e.code === "ENOTFOUND" || e.code === "ESERVFAIL") // If DNS doesn't resolve, it's not (definitely) vulnerable - prob an internal service
                {
                    const output = {
                        vulnerable: false,
                        message: ""
                    };

                    return resolve(output);
                }

            return reject(e);
        }
    });
}

// newshub-live-mosdatastore.newsonline.tc.nca.bbc.co.uk is a SERVFAIL and flags as vulnerable but since it doesn't exist, it isn't
// might need to initially check if we get ESERVFAIL

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
            return reject(e);
        }
    });
}

// Takes and array of hostnames, checks if they're orphaned DNS delegations (they have an NS record which is an NXDOMAIN), returns a boolean
async function isHostnameOrphanedDelegation(hostname, Resolver, safeNameservers = {}) {
    if (!(typeof hostname === 'string')) {
        throw new TypeError("Value of argument \"hostname\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(hostname));
    }

    if (!(Resolver instanceof Object)) {
        throw new TypeError("Value of argument \"Resolver\" violates contract.\n\nExpected:\nObject\n\nGot:\n" + _inspect(Resolver));
    }

    if (!(safeNameservers instanceof Object)) {
        throw new TypeError("Value of argument \"safeNameservers\" violates contract.\n\nExpected:\nObject\n\nGot:\n" + _inspect(safeNameservers));
    }

    // TODO: Refactor this into sub-functions, this is too looooooong    
    return new Promise(async (resolve, reject) => {
        const response = {
            vulnerable: false,
            reasonCode: "",
            reason: "",
            severity: ""
        };

        try {
            const mainResolver = new Resolver();
            const NSResolver = new Resolver();

            let nameservers = [];
            let resolverSOA = {};

            // Check if the hostname _is_ delegated, exit early if not
            try {
                nameservers = await mainResolver.resolveNs(hostname);
            } catch (e) {
                if (e.code === "ENOTFOUND") // hostname is not delegated (there are no NSs or no SOA)
                    {
                        // Check if the NS is an IP address as those records will fail resolveNs() with ENOTFOUND
                        response.reason = `${hostname} is not delegated`;
                        response.reasonCode = "HOSTNAME_NOT_DELEGATED";
                        return resolve(response);
                    } else if (e.code === "ESERVFAIL") // This happens on an orphaned hostname e.g. ns-not-exists-local.thedotproduct.org which has non-existant NS destinations
                    {
                        // is this always an orphaned sub-domain?
                        response.reason = `No nameservers found in DNS for ${hostname}`;
                        response.reasonCode = "HOSTNAME_NS_SERVFAIL";
                        return resolve(response);
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

                            if (_assert2.default.deepStrictEqual(resolverSOA, nameserverSOA) === false) // The SOA on the nameserver which the hostname points to has a mismatched SOA, thus it may be vulnerable
                                {
                                    response.reason = `Nameserver ${nameserver} has a mismatched (versus other nameservers) SOA record for ${hostname}`;
                                    response.reasonCode = "NS_HAS_MISMATCHED_SOA";
                                    response.vulnerable = true;
                                    response.severity = "MEDIUM"; // Should this be "LOW"?
                                    return resolve(response);
                                }
                        } catch (e) {
                            if (e.code === "ENOTFOUND") // The nameserver which the hostname points to has no SOA for the hostname (i.e. it doesn't have a zone for it)
                                {
                                    response.reason = `Nameserver ${nameserver} has no SOA record for ${hostname}`;
                                    response.reasonCode = "NS_HAS_NO_SOA";
                                    response.vulnerable = true;
                                    response.severity = "MEDIUM"; // Should this be "LOW"?
                                    return resolve(response);
                                } else if (e.code === "ESERVFAIL") // The nameserver which the hostname points to has no records for the hostname (i.e. it doesn't have a zone for it)
                                {
                                    response.reason = `Nameserver ${nameserver} has no records for ${hostname}`;
                                    response.reasonCode = "NS_HAS_NO_RECORDS";
                                    response.vulnerable = true;
                                    response.severity = "HIGH"; // Should this be "LOW"?
                                    return resolve(response);
                                }
                        }
                    } catch (e) // If we end up here, the NS record didn't resolve, which could be a takeover vulnerability (if someone else owns the domain name)
                    {
                        // Check if the nameserver IP is an IP address, if so, check if it's an "OK" IP address
                        if ((0, _net.isIP)(nameserver)) {
                            // TODO:
                            // add CLI arg to pass ^ in, 3 separate files for safe nameservers: ipv4 ipv6, hostname 
                            if ((0, _net.isIPv4)(nameserver)) {
                                if (safeNameservers.ipv4) {
                                    _safeNameservers$ipv = safeNameservers.ipv4;

                                    if (!(_safeNameservers$ipv && (typeof _safeNameservers$ipv[Symbol.iterator] === 'function' || Array.isArray(_safeNameservers$ipv)))) {
                                        throw new TypeError("Expected _safeNameservers$ipv to be iterable, got " + _inspect(_safeNameservers$ipv));
                                    }

                                    for (let safeIP of _safeNameservers$ipv) {
                                        var _safeNameservers$ipv;

                                        const safe = (0, _ipRangeCheck2.default)(nameserver, safeIP);
                                        if (safe) {
                                            response.reason = `${hostname} is delegated to IP-based nameserver but it's on the IPv4 safe list`;
                                            response.reasonCode = "IP_NS_ON_V4_SAFE_LIST";
                                            response.vulnerable = false;
                                            return resolve(response);
                                        }
                                    }
                                }
                            }

                            if ((0, _net.isIPv6)(nameserver)) {
                                if (safeNameservers.ipv6) {
                                    _safeNameservers$ipv2 = safeNameservers.ipv6;

                                    if (!(_safeNameservers$ipv2 && (typeof _safeNameservers$ipv2[Symbol.iterator] === 'function' || Array.isArray(_safeNameservers$ipv2)))) {
                                        throw new TypeError("Expected _safeNameservers$ipv2 to be iterable, got " + _inspect(_safeNameservers$ipv2));
                                    }

                                    for (let safeIP of _safeNameservers$ipv2) {
                                        var _safeNameservers$ipv2;

                                        const safe = (0, _ipRangeCheck2.default)(nameserver, safeIP);
                                        if (safe) {
                                            response.reason = `${hostname} is delegated to IP-based nameserver but it's on the IPv6 safe list`;
                                            response.reasonCode = "IP_NS_ON_V6_SAFE_LIST";
                                            response.vulnerable = false;
                                            return resolve(response);
                                        }
                                    }
                                }
                            }

                            response.reason = `Nameserver ${nameserver} (IP address) does not resolve`;
                            response.reasonCode = "IP_NS_DOESNT_RESOLVE";
                            response.vulnerable = true;
                            response.severity = "HIGH"; // Should this be "LOW"?
                            return resolve(response);
                        }

                        response.reason = `Nameserver ${nameserver} does not resolve`;
                        response.reasonCode = "NS_DOESNT_RESOLVE";
                        response.vulnerable = true;
                        response.severity = "HIGH"; // Should this be "LOW"?
                        return resolve(response);
                    }
                }
            }

            response.reason = `${hostname} is not delegated`;
            response.reasonCode = "HOSTNAME_NOT_DELEGATED";
            return resolve(response);
        } catch (e) {
            // Some DNS queries will error but are not a problem, we'll handle those here
            if (e.code === "ENODATA") // This happens when: hostname has no NS record (thus it cannot be vulnerable)
                {
                    response.reason = `${hostname} has no NS records`;
                    response.reasonCode = "HOSTNAME_HAS_NO_NS";
                    return resolve(response);
                } else if (e.code === "ENOTFOUND") // This happens when: hostname is NXDOMAIN (thus it cannot be vulnerable)
                {
                    response.reason = `${hostname} has no DNS records (NXDOMAIN)`;
                    response.reasonCode = "HOSTNAME_IS_NXDOMAIN";
                    return resolve(response);
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

            if (!(typeof RSSURL === 'string')) {
                throw new TypeError("Value of variable \"RSSURL\" violates contract.\n\nExpected:\nstring\n\nGot:\n" + _inspect(RSSURL));
            }

            const parsedRSS = await parser.parseURL(RSSURL);

            if (!(parsedRSS instanceof Object)) {
                throw new TypeError("Value of variable \"parsedRSS\" violates contract.\n\nExpected:\nObject\n\nGot:\n" + _inspect(parsedRSS));
            }

            const certificates = getCertificatesFromRSSItems(parsedRSS.items);

            if (!Array.isArray(certificates)) {
                throw new TypeError("Value of variable \"certificates\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(certificates));
            }

            const SANS = getSANSFromCertificatesArray(certificates);

            if (!Array.isArray(SANS)) {
                throw new TypeError("Value of variable \"SANS\" violates contract.\n\nExpected:\nArray\n\nGot:\n" + _inspect(SANS));
            }

            let augmentedHostnames = new Set();

            // Replace "*.<domain name>" with N sub-domains from popular sub-domains list...

            if (!(SANS && (typeof SANS[Symbol.iterator] === 'function' || Array.isArray(SANS)))) {
                throw new TypeError("Expected SANS to be iterable, got " + _inspect(SANS));
            }

            for (let SANEntry of SANS) {
                // ...initially we'll only do this for hostnames which begin with *. (but we could do it for all, i guess)
                if (SANEntry.match(/^\*\./)) {
                    const subDomainEnding = SANEntry.replace(/^\*\./, "");

                    if (!(subDomainPrefixes && (typeof subDomainPrefixes[Symbol.iterator] === 'function' || Array.isArray(subDomainPrefixes)))) {
                        throw new TypeError("Expected subDomainPrefixes to be iterable, got " + _inspect(subDomainPrefixes));
                    }

                    for (let prefix of subDomainPrefixes) {
                        const subDomain = `${prefix}.${subDomainEnding}`;
                        augmentedHostnames.add(subDomain);
                    }
                } else if (SANEntry.length) {
                    augmentedHostnames.add(SANEntry);
                }
            }

            const hostnames = Array.from(augmentedHostnames);
            return resolve(hostnames);
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
    readFileContentsIntoArray: readFileContentsIntoArray,
    isHostnameOrphaned: isHostnameOrphaned,
    getDomainNamesFromNameserver: getDomainNamesFromNameserver
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