"use strict";

// TODO: have a specific var for the lib filename and use that for consistency
// import {default as config} from "../config/sub-domain-scanner-config.js"; // NOTE: Path is relative to build dir (dist/)
import {getHostnamesFromCTLogs} from "./lib/sub-domain-scanner-lib.js"; // NOTE: Path is relative to build dir (dist/) - local because lib is babel'd


/*
    TODO:
    * yargs it up
    * add tests for existing fns
    * add flag for "only check valid/unexpired certs" (default: yes) - QS: &exclude=expired
    * think about arch and plan accordingly
    * allow for limiting scope to specific domain(s) (e.g. *.bbc.co.uk only) - e.g. --limit-scope=[bbc.co.uk,bbc.com]
    * could recurse onto discovered hostnames (need to set how many deep)
    * test types:
        * check orphaned zone delegations - got NS record but no result when `dig @<ns> any <hostname>`
        * check for cnames to 3rd party services
            * if s3, gcs etc. then check if service exists
            * check if dest domain is unregistered
            * check owner of domain, higher pri if not target org
        * check for a -> IPs not owned
            * make TLS connection to IP with servername and checkif hostname is on cert
            * poss check for keyword (brand name) in HTML - might be buggy esp on JS sites with no fallback
            * whois?
        * show each IP (A, AAAA, CNAME etc.) by AS
        * check server banners for typical services e.g. http, ftp, sftp, ssh - out of date versions CVEs
    * poss add option to use DNS recon to augment
    * add web crawler to pick up additional domains
    * add option to only output hostnames
    * add option to skip recon and just test list of hostnames
    * output should be ranked/grouped by severity
        * critical, high, medium, low, no risk
*/


async function main()
{
    // NOTE: this won't actually be the fn that gets called, it'll be e.g. run(<opts>)
    const CTLogs = await getHostnamesFromCTLogs("www.thedotproduct.org");

    for(let hostname of CTLogs)
    {
        console.log(`${hostname}`);
    }

    console.log(`Found ${CTLogs.length} hostnames`);
}

main();