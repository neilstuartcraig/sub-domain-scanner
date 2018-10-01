"use strict";

import {default as config} from "../../config/sub-domain-scanner-config.js"; // NOTE: Path is relative to build dir (dist/)

import {escape} from "querystring";
import {default as Parser} from "rss-parser";
import {default as x509} from "x509-parser";

import {EOL} from "os";

const parser = new Parser({
    customFields: {
        item: ["summary"]
    }
});


// Takes an input arg of the RSS object "items" property and returns an Array of X509 certificates
function getCertificatesFromRSSItems(RSSItems: Array)
{
    const certificates = RSSItems.map((item) => 
    {
        const rawSummary = item.summary._;
        const certificate = rawSummary.match(/-----BEGIN CERTIFICATE-----(.+)-----END CERTIFICATE-----/)[0].replace(/<br>/g, EOL);
        return certificate;
    });

    return certificates;
}

// Takes an input of an Array of X509 certificates and returns a de-duped Array of SAN hostnames
function getSANSFromCertificatesArray(certificatesArray: Array)
{
    let hostnamesSet = new Set();

    for(let certificate of certificatesArray)
    {
        const SANS = x509.getAltNames(certificate); // Array

        for(let hostname of SANS) 
        {
            hostnamesSet.add(hostname.toLowerCase());
        }    
    }

    const rawHostnames = Array.from(hostnamesSet);
    const hostnames = rawHostnames.sort();
    return hostnames;
}

function getRSSURLFromHostname(hostname: string)
{
    const URLEncodedHostname = escape(hostname.replace(/^\*/, "%"));
    const URL = `${config.crtshRSSURLPrefix}${URLEncodedHostname}`;
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
    getHostnamesFromCTLogs: getHostnamesFromCTLogs
};
