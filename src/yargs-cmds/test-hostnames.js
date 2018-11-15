"use strict";

import {EOL} from "os";
import {default as getstdin} from "get-stdin";
const {Resolver} = require("dns").promises;
import {get as axiosGet} from "axios";


import {isHostnameOrphanedDelegation, readFileContentsIntoArray, isHostnameOrphaned} from "../lib/sub-domain-scanner-lib.js"; // NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

const hostnamesFileOpt = 
{
    alias: ["hostnames-file", "hosts-file", "hf", "f"],
    demandOption: true,
    type: "string", 
    description: "A filename which contains hostnames to test (one file per line). usage: --hostnames-file /path/to/file or --hostnames-file - (to use stdin)"
};

let mod = 
{
    // Command name - i.e. gtm-cli <command name> <options>
    command: "test-hostnames",

    // Command description
    desc: "Test hostnames for takeover vulnerabilities",

    // Define command options
    builder: 
    {
        hostnamesFile: hostnamesFileOpt
    },

    // Handler/main function - this is executed when this command is requested
    handler: async (argv) => 
    {
        try
        {
            // read/handle file/stdin
            // iterate through each hostname
            // check if sub-domain has NS
            //  y: check if orphaned delegation (e.g. dig ns <domain> and check for records then for each NS, dig@<NS> an <domain> and check for NXDOMAIN)
            // check if CNAME to 3rd party host and !configured (S3 etc), medium: missing all entries in array of strings (arg) (i.e. pointing to outdated dest) - could maybe do via a scoring system. could check if has TLS cert not owned by main site owner but that should show in CT
            // check if A/AAAA to IP not controlled by owner and not responds

            let hostnames: Array = [];

            if(argv.hostnamesFile === "-") // use stdin
            {
                const stdin: string = await getstdin();

                if(stdin.length)
                {
                    const re = new RegExp(EOL, "g");
                    hostnames = stdin.trim().replace(re, " ").split(" "); // We have to replace newlines with space because the output from discover-hostnames is newline-separated      
                }
                else
                {
                    console.error("Please supply a space-separated list of hostnames to test");
                    process.exit(1);
                }
            }
            else // use file
            {           
                try
                {
                    // read file in from disk + make an array
                    hostnames = await readFileContentsIntoArray(argv.hostnamesFile);
                }
                catch(e)
                {
                    // TODO: Handle errors in a more friendly way
                    console.error(e);
                    process.exit(1);
                }
            }

            for(let hostname of hostnames)
            {
                const isVulnerableDelegation = await isHostnameOrphanedDelegation(hostname, Resolver, axiosGet);
if(isVulnerableDelegation.vulnerable)
{
console.log(`${hostname} - vuln? ${JSON.stringify(isVulnerableDelegation, null, 2)}`);                
}

// TODO: in discover, add https://hackertarget.com/find-shared-dns-servers/ - seems to find a lot of related domains - try search for ns4.bbc.co.uk

                // TODO: reduce DNS lookups - perhaps do a single lookup per hostname and feed the results into other checker functions

                // test whether orphaned here
                const isOrphaned: Object = await isHostnameOrphaned(hostname, Resolver, axiosGet); // TODO: rename isOrphaned
                if(isOrphaned.vulnerable)
                {
console.log("errz");                    
console.error(isOrphaned.message);                    
                }
// TODO: auto takeover for s3 etc.

// TODO: more checks
//

            }

            // console.log(output);
            process.exit(0);
        }
        catch(e)
        {
console.log("throwing here - test-hostname. need to find in lib");            
            console.error(e.message);
            process.exit(1);
        }
    }
};

// exports.default = mod;
module.exports = mod;