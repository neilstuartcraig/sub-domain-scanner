"use strict";

import {default as config} from "../../config/sub-domain-scanner-config.js"; // NOTE: Path is relative to build dir (dist/)

import {default as assert} from "assert";
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
            let resolverSOA = {};
console.log(`hostname to test: ${hostname}`);
            // Check if the hostname _is_ delegated, exit early if not
            try
            {
                nameservers = await resolver.resolveNs(hostname);
                resolverSOA = await resolver.resolveSoa(hostname);          
            }
            catch(e)
            {
console.log("error on resolving hostname NS and SOA");                
console.dir(e);                
                if(e.code === "ENOTFOUND") // hostname is not delegated (there are no NSs or SOA)
                {
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

// TODO:
// this lookup fails for thedotproduct.org    
// i think it's failing to resolve the NS IP against another NS IP - because the resolver.setServers(nameserverIP) leaves a lingerig change
// could use 2x resolver instances? or maybe reset it?                  
// you can't just resolver.setServers(); or resolver.setServers([]]); - those fail
resolver.setServers(["8.8.8.8"]);
                        nameserverIP = await resolver.resolve4(nameserver);

                        console.log(`setting NS to ${nameserverIP}`);                    
resolver.setServers(nameserverIP);

                        try
                        {
console.log(`querying NS: ${nameserverIP} for ${hostname}`);                        
                            const nameserverSOA = await resolver.resolveSoa(hostname);
console.log("NS SOA:");                        
console.dir(nameserverSOA);
console.log("RESOLVER SOA:");
console.dir(resolverSOA);

                            if(assert.deepStrictEqual(resolverSOA, nameserverSOA) === false)
                            {
console.log("NS SOA !== RSOA");          
                                return resolve(true);
                            }
                            
                        }
                        catch(e)
                        {
console.log("ns query err:");                        
console.dir(e);                        
                            if(e.code === "ENOTFOUND")
                            {
                                return resolve(true); 
                            }
                        }
                    }
                    catch(e) // If we end up here, the NS IP didn't resolve, thus there's a potential vulnerability if the NS (esp. if the NS hostname is remote)
                    {
console.log(`error on resolving A record for NS ${nameserver}`);              
// might be that the NS can't resolve itself?   
console.dir(e);                     
                        if(e.code === "ENOTFOUND")
                        {
// this is where test1 fails (if below is not commented out) - is there any reason we can confidently state here that the delegation _is_ orphaned?
                            // return resolve(true); // NOTE: this will happen for  NXDOMAIN on the NS destination
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
