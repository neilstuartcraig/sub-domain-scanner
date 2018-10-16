"use strict";

import {default as config} from "../../config/sub-domain-scanner-config.js"; // NOTE: Path is relative to build dir (dist/)

import {default as assert} from "assert";
import {escape} from "querystring";
import {default as Parser} from "rss-parser";
import {default as x509} from "x509-parser";

const {Resolver} = require("dns").promises;
import {resolve as resolvePaths} from "path";
const fsp = require("fs").promises;
import {EOL} from "os";

const parser = new Parser(
{
    customFields:
    {
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
            reject(e);
        }
    });
}

// Takes and array of hostnames, checks if they're orphaned DNS delegations (they have an NS record which is an NXDOMAIN), returns a boolean
async function isHostnameOrphanedDelegation(hostname: string)
{
    return new Promise(async (resolve, reject) => 
    {
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
                resolverSOA = await mainResolver.resolveSoa(hostname);          
            }
            catch(e)
            {
                if(e.code === "ENOTFOUND") // hostname is not delegated (there are no NSs or no SOA)
                {
// TODO: #NSIsAnIP                   
// need a check here to see if the NS is an IP address as those records will fail resolveNs() with ENOTFOUND
// unsure how best to tackle this though, doesn't seem to be doable in node :-(

                    return resolve(false);
                }
                else if(e.code === "ESERVFAIL") // This happens on an orphaned hostname e.g. ns-not-exists-local.thedotproduct.org which has non-existant NS destinations
                {
                    // is this always an orphaned sub-domain?
                    return resolve(true);
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

                            if(assert.deepStrictEqual(resolverSOA, nameserverSOA) === false)
                            {
                                return resolve(true);
                            }
                        }
                        catch(e)
                        {
                            if(e.code === "ENOTFOUND")
                            {
                                return resolve(true); 
                            }
                        }
                    }
                    catch(e) // If we end up here, the NS IP didn't resolve, which could be a takeover vulnerability (if someone else owns the IP)
                    {
                        return resolve(true);        
                    }
                }
            }

            return resolve(false);
        }
        catch(e)
        {
            // Some DNS queries will error but are not a problem, we'll handle those here
            if(e.code === "ENODATA") // This happens when: hostname has no NS record
            {
                return resolve(false);
            }
            else if (e.code === "ENOTFOUND") // This happens when: hostname is NXDOMAIN
            {               
                return resolve(false);
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
    readFileContentsIntoArray: readFileContentsIntoArray
};
