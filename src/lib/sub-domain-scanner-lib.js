"use strict";

import {default as config} from "../../config/sub-domain-scanner-config.js"; // NOTE: Path is relative to build dir (dist/)

import {default as assert} from "assert";
import {escape} from "querystring";
import {default as Parser} from "rss-parser";
import {default as x509} from "x509-parser";
import {default as IPRangeCheck} from "ip-range-check";


import {resolve as resolvePaths} from "path";
const fsp = require("fs").promises;
import {EOL} from "os";
import {isIP, isIPv4, isIPv6} from "net";


const parser = new Parser(
{
    customFields:
    {
        item: ["summary"]
    }
});


// TODO: mnove this to config or somewhere more sensible
// NOTE: This borrows and is inspired by https://github.com/EdOverflow/smith/blob/master/smith
const thirdPartyServicesChecks = 
[
    {
        "name": "AWS S3 bucket",
        "hostnameRegex": /s3\-.+\.amazonaws\.com$/i,
        "scheme": "https",
        "responseStatusForNonExisting": 404,
        "responseBodyMatchForNonExisting": "NoSuchBucket"
    },
    {
        "name": "Google Cloud Storage bucket",
        "hostnameRegex": /^c\.storage\.googleapis\.com$/i,
        "scheme": "https",
        "responseStatusForNonExisting": 404,
        "responseBodyMatchForNonExisting": "InvalidBucketName"
    },
    {
        "name": "Cloudfront distribution",
        "hostnameRegex": /.+\.cloudfront\.net$/i,
        "scheme": "https",
        "responseStatusForNonExisting": 404,
        "responseBodyMatchForNonExisting": "The request could not be satisfied"
    },
    {
        "name": "Fastly configuration",
        "hostnameRegex": /.+\.fastly\.net$/i,
        "scheme": "http",
        "responseStatusForNonExisting": null,
        "responseBodyMatchForNonExisting": "Fastly error: unknown domain"
    },
    {
        "name": "github.io account",
        "hostnameRegex": /.+\.github\.io$/i,
        "scheme": "https",
        "responseStatusForNonExisting": 404,
        "responseBodyMatchForNonExisting": "There isn't a GitHub Pages site here."
    },
    {
        "name": "Zendesk account",
        "hostnameRegex": /.+\.zendesk\.com$/i,
        "scheme": "http",
        "responseStatusForNonExisting": 200, // NOTE: This is the result of a 301
        "responseBodyMatchForNonExisting": "Bummer. It looks like the help center that you are trying to reach no longer exists."
    },
    {
        "name": "Wordpress.com hosting account",
        "hostnameRegex": /.+\.wordpress\.com$/i,
        "scheme": "https",
        "responseStatusForNonExisting": 200,
        "responseBodyMatchForNonExisting": /.+wordpress\.com\<\/em> doesn&#8217;t&nbsp;exist/g
    },
    {
        "name": "Heroku app",
        "hostnameRegex": /.+herokuapp\.com$/i,
        "scheme": "http",
        "responseStatusForNonExisting": 404,
        "responseBodyMatchForNonExisting": "<iframe src=\"//www.herokucdn.com/error-pages/no-such-app.html\"></iframe>"
    }
    // TODO: Add more!
];

const axiosGetConfig = 
{
    validateStatus: () => 
    {
        return true;
    }
};

// TODO: add discovery method using https://api.hackertarget.com/findshareddns/?q=ns1.bbc.co.uk
async function getDomainNamesFromNameserver(nameserver: string, axiosGetFn: Function)
{
    return new Promise(async (resolve, reject) => 
    {
        try
        {
            // TODO: better filtering to avoid security issues with nameserver var content
            const serviceURL: string = `https://api.hackertarget.com/findshareddns/?q=${nameserver}`;        
            const response: Object = await axiosGetFn(serviceURL, axiosGetConfig);
            const domains: Array = response.data.trim().split(EOL);
            return resolve(domains);
        }
        catch(e)
        {
            return reject(e);
        }
    });
}


// TODO: ignore hostnames which are wildcarded e.g. *.api.bbc.co.uk 


// Takes a DNS recordset and tests whether it is a CNAME to a 3rd party storage service e.g. AWS S3
async function isHostnameCNameTo3rdParty(hostname: string, cnames: Array, axiosGetFn: Function)
{
    let output: Object = 
    {
        "vulnerable": false,
        "reasonCode": "",
        "reason": "",
        "severity": ""
    }; 

    for(let cname of cnames)
    {
        for(let thirdPartyServiceCheckConfig of thirdPartyServicesChecks)
        {
            if(cname.match(thirdPartyServiceCheckConfig.hostnameRegex))
            {           
                try
                {
                    const serviceURL = `${thirdPartyServiceCheckConfig.scheme}://${cname}/`;        
                    const response = await axiosGetFn(serviceURL, axiosGetConfig);

                    if(response.data.match(thirdPartyServiceCheckConfig.responseBodyMatchForNonExisting) && response.status === thirdPartyServiceCheckConfig.responseStatusForNonExisting)
                    {                      
                        output.vulnerable = true; 
                        output.reason = `${hostname} is a CNAME to ${cname} (unconfigured ${thirdPartyServiceCheckConfig.name})`;
                        output.reasonCode = `CNAMED_TO_UNCONFIGURED_3RD_PARTY_SVC`;
                        output.severity = "high";
                        break; // Presumably, it's not possible for a single cname to be directed at >1 storage service (?)
                    }
                }
                catch(e)
                {    
                    if(e.code === "ENOTFOUND")
                    {
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
async function isHostnameOrphaned(hostname: string, Resolver: Object, axiosGetFn: Function) // TODO: consider adding an object arg containing "safe" destinations
{
    return new Promise(async (resolve, reject) => 
    {
        try
        {
            // Check for 
                // cname to 3rd party e.g. S3/GCS/CDN
                    // see https://github.com/EdOverflow/smith/blob/master/smith
                    // See https://github.com/EdOverflow/can-i-take-over-xyz
                // A -> 3rd party IP (v4/v6)

            const resolver = new Resolver();
            const cnames = await resolver.resolveCname(hostname); 

            const isCNamedTo3rdParty = isHostnameCNameTo3rdParty(hostname, cnames, axiosGetFn);

            return resolve(isCNamedTo3rdParty);

        }
        catch(e)
        {
            if(e.code === "ENODATA" || e.code === "ENOTFOUND" || e.code === "ESERVFAIL") // If DNS doesn't resolve, it's not (definitely) vulnerable - prob an internal service
            {
                const output = 
                {
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

async function readFileContentsIntoArray(filename: string, separator: string = EOL, fileEncoding: string = "utf8", outputCharset: string = "utf8")
{
    return new Promise(async (resolve, reject) => 
    {
        try
        {
            const filenameAndPath: string = resolvePaths(filename);
            const fileContent: string = await fsp.readFile(filenameAndPath, fileEncoding);
            const output: Array = fileContent.trim().split(separator).filter((val) => 
            {
                return val.length; // Filter out empty values
            });
            return resolve(output);
        }
        catch(e)
        {
            return reject(e);
        }
    });
}

// Takes and array of hostnames, checks if they're orphaned DNS delegations (they have an NS record which is an NXDOMAIN), returns a boolean
async function isHostnameOrphanedDelegation(hostname: string, Resolver: Object, safeNameservers: Object = {})
{
// TODO: Refactor this into sub-functions, this is too looooooong    
    return new Promise(async (resolve, reject) => 
    {
        const response = 
        {
            vulnerable: false,
            reasonCode: "",
            reason: "",
            severity: ""
        };

        try
        {
            const mainResolver = new Resolver();
            const NSResolver = new Resolver();

            let nameservers = [];
            let resolverSOA = {};

            // Check if the hostname _is_ delegated, exit early if not
            try
            {
                nameservers = await mainResolver.resolveNs(hostname);   
            }
            catch(e)
            {
                if(e.code === "ENOTFOUND") // hostname is not delegated (there are no NSs or no SOA)
                {
                    // Check if the NS is an IP address as those records will fail resolveNs() with ENOTFOUND
                    response.reason = `${hostname} is not delegated`;
                    response.reasonCode = "HOSTNAME_NOT_DELEGATED";
                    return resolve(response);
                }
                else if(e.code === "ESERVFAIL") // This happens on an orphaned hostname e.g. ns-not-exists-local.thedotproduct.org which has non-existant NS destinations
                {
                    // is this always an orphaned sub-domain?
                    response.reason = `No nameservers found in DNS for ${hostname}`;
                    response.reasonCode = "HOSTNAME_NS_SERVFAIL";
                    return resolve(response);
                }
            }

            if(nameservers.length)
            {
                for(let nameserver of nameservers)
                {
                    let nameserverIP = "";

                    try // this requires a separate try/catch so that we can definitely determine that the NS DNS resolution fails
                    {
                        // We'll directly query the nameserver below, for which we need the IP as setServers doesn't accept a hostname
                        // At some point, we'll need to also/instead use IPv6 resolution, but I CBA right now
                        nameserverIP = await mainResolver.resolve4(nameserver);
                        NSResolver.setServers(nameserverIP);

                        try
                        {
                            const nameserverSOA = await NSResolver.resolveSoa(hostname);

                            if(assert.deepStrictEqual(resolverSOA, nameserverSOA) === false) // The SOA on the nameserver which the hostname points to has a mismatched SOA, thus it may be vulnerable
                            {               
                                response.reason = `Nameserver ${nameserver} has a mismatched (versus other nameservers) SOA record for ${hostname}`;
                                response.reasonCode = "NS_HAS_MISMATCHED_SOA";
                                response.vulnerable = true;
                                response.severity = "MEDIUM"; // Should this be "LOW"?
                                return resolve(response);
                            }
                        }
                        catch(e)
                        {            
                            if(e.code === "ENOTFOUND") // The nameserver which the hostname points to has no SOA for the hostname (i.e. it doesn't have a zone for it)
                            {
                                response.reason = `Nameserver ${nameserver} has no SOA record for ${hostname}`;
                                response.reasonCode = "NS_HAS_NO_SOA";
                                response.vulnerable = true;
                                response.severity = "MEDIUM"; // Should this be "LOW"?
                                return resolve(response);
                            }
                            else if(e.code === "ESERVFAIL") // The nameserver which the hostname points to has no records for the hostname (i.e. it doesn't have a zone for it)
                            {
                                response.reason = `Nameserver ${nameserver} has no records for ${hostname}`;
                                response.reasonCode = "NS_HAS_NO_RECORDS";
                                response.vulnerable = true;
                                response.severity = "HIGH"; // Should this be "LOW"?
                                return resolve(response);
                            }
                        }
                    }
                    catch(e) // If we end up here, the NS record didn't resolve, which could be a takeover vulnerability (if someone else owns the domain name)
                    {
                        // Check if the nameserver IP is an IP address, if so, check if it's an "OK" IP address
                        if(isIP(nameserver))
                        {
// TODO:
// add CLI arg to pass ^ in, 3 separate files for safe nameservers: ipv4 ipv6, hostname 
                            if(isIPv4(nameserver))
                            {                          
                                if(safeNameservers.ipv4)
                                {
                                    for(let safeIP of safeNameservers.ipv4)
                                    {
                                        const safe = IPRangeCheck(nameserver, safeIP);
                                        if(safe)
                                        {
                                            response.reason = `${hostname} is delegated to IP-based nameserver but it's on the IPv4 safe list`;
                                            response.reasonCode = "IP_NS_ON_V4_SAFE_LIST";
                                            response.vulnerable = false;
                                            return resolve(response);
                                        }
                                    }
                                }
                            }
                            
                            if(isIPv6(nameserver))
                            {
                                if(safeNameservers.ipv6)
                                {
                                    for(let safeIP of safeNameservers.ipv6)
                                    {                                        
                                        const safe = IPRangeCheck(nameserver, safeIP);
                                        if(safe)
                                        {
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
        }
        catch(e)
        {
            // Some DNS queries will error but are not a problem, we'll handle those here
            if(e.code === "ENODATA") // This happens when: hostname has no NS record (thus it cannot be vulnerable)
            {
                response.reason = `${hostname} has no NS records`;
                response.reasonCode = "HOSTNAME_HAS_NO_NS";
                return resolve(response);
            }
            else if (e.code === "ENOTFOUND") // This happens when: hostname is NXDOMAIN (thus it cannot be vulnerable)
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
function filterHostnames(hostnames: Array, mustMatch: RegExp, mustNotMatch: RegExp)
{
    const filteredHostnames = hostnames.filter((hostname) => 
    {
        if(hostname.match(mustMatch) && !hostname.match(mustNotMatch))
        {
            return true;
        }

        return false;
    });

    return filteredHostnames;
}

// Takes an input arg of the RSS object "items" property and returns an Array of X509 certificates
function getCertificatesFromRSSItems(RSSItems: Array)
{
    const certificates: Array = RSSItems.map((item) => 
    {
        try
        {
            const rawSummary: string = item.summary._;
            const certificate: string = rawSummary.match(/-----BEGIN CERTIFICATE-----(.+)-----END CERTIFICATE-----/)[0].replace(/<br>/g, EOL);
            return certificate;
        }
        catch(e)
        {
            return undefined;
        }
    }).filter((cert) => cert !== undefined); // Filter out any invalid certs

    return certificates;
}

// Takes an input of an Array of X509 certificates and returns a de-duped, sorted Array of SAN hostnames
function getSANSFromCertificatesArray(certificatesArray: Array)
{
    let hostnamesSet = new Set();

    for(let certificate of certificatesArray) // Note: we don't type-check certificate as it'll throw if we do and it's wrong
    {
        try
        {
            const SANS: Array = x509.getAltNames(certificate); // Array

            for(let hostname: string of SANS) 
            {
                hostnamesSet.add(hostname.toLowerCase());
            }    
        }
        catch(e)
        {
            // we don't need to do anything here(?), the certificate is wrongly formatted so we ignore it
        }

    }

    const rawHostnames: Array = Array.from(hostnamesSet);
    const hostnames: Array = rawHostnames.sort();
    return hostnames;
}

function getRSSURLFromHostname(hostname: string)
{
    const URLEncodedHostname = escape(hostname.replace(/^\*/, "%"));
    const URL: string = `${config.crtshRSSURLPrefix}${URLEncodedHostname}`;
    return URL;
}

async function getHostnamesFromCTLogs(hostname: string)
{
    return new Promise(async (resolve, reject) => 
    {
        try
        {
            const RSSURL = getRSSURLFromHostname(hostname);        
            const parsedRSS = await parser.parseURL(RSSURL);
            const certificates = getCertificatesFromRSSItems(parsedRSS.items);
            const SANS = getSANSFromCertificatesArray(certificates);
            return resolve(SANS);
        }
        catch(e)
        {      
            return reject(e);
        }
    });
}


module.exports =
{
    getCertificatesFromRSSItems: getCertificatesFromRSSItems,
    getSANSFromCertificatesArray: getSANSFromCertificatesArray,
    getRSSURLFromHostname: getRSSURLFromHostname,
    getHostnamesFromCTLogs: getHostnamesFromCTLogs,
    filterHostnames: filterHostnames,
    isHostnameOrphanedDelegation:isHostnameOrphanedDelegation,
    readFileContentsIntoArray: readFileContentsIntoArray,
    isHostnameOrphaned: isHostnameOrphaned,
    getDomainNamesFromNameserver: getDomainNamesFromNameserver
};
