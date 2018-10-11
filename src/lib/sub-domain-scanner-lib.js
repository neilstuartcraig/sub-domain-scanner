"use strict";

import {default as config} from "../../config/sub-domain-scanner-config.js"; // NOTE: Path is relative to build dir (dist/)

import {escape} from "querystring";
import {default as Parser} from "rss-parser";
import {default as x509} from "x509-parser";

const {Resolver} = require("dns").promises;

import {EOL} from "os";

const parser = new Parser(
{
    customFields:
    {
        item: ["summary"]
    }
});


// Takes and array of hostnames, checks if they're orphaned DNS delegations (they have an NS record which is an NXDOMAIN), returns a boolean
async function isHostnameOrphanedDelegation(hostname: string)
{
    return new Promise(async (resolve, reject) => 
    {
        try
        {
            const resolver = new Resolver();

            let nameservers = [];

            try
            {
                nameservers = await resolver.resolveNs(hostname);
            }
            catch(e)
            {
                if(e.code === "ENOTFOUND")
                {
                    return resolve(false);
                }
            }

            if(nameservers.length)
            {
                for(let nameserver of nameservers)
                {
                    let nameserverIP = "";

                    try // this requires a separate try/catch so that we can definitely determine that the NS DNS resolution fails
                    {
                        nameserverIP = await resolver.resolve4(nameserver);
                    }
                    catch(e) // If we end up here, the NS IP didn't resolve, thus there's a potential vulnerability if the NS (esp. if the NS hostname is remote)
                    {
                        return resolve(true); // NOTE: this will happen for either NXDOMAIN on the NS destination
                    }

                    resolver.setServers(nameserverIP);

                    try
                    {
                        const records = await resolver.resolveAny(hostname);

                        if(records.length)
                        {
                            return resolve(false); // NOTE: This will happen if the NS exists but has no records for the hostname
                        }
                    }
                    catch(e)
                    {
                        if(e.code === "EREFUSED")
                        {


// argh, cloudflare refuses "any" queries on some domains:
/*
HINFO	"ANY obsoleted" "See draft-ietf-dnsop-refuse-any"

what do we do here?
*/

                            return resolve(true); //?
                        }
                    }
                }

                return resolve(true);
            }

            return resolve(false);
        }
        catch(e)
        {
            // Some DNS queries will error but are not a problem, we'll handle those here
            if(e.code === "ENODATA") // This happens when: hostname has no NS record
            {
                resolve(false);
            }
            else if (e.code === "ENOTFOUND") // This happens when: hostname is NXDOMAIN
            {               
                resolve(false);
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
    isHostnameOrphanedDelegation:isHostnameOrphanedDelegation 
};
