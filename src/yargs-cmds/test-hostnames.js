"use strict";

import {EOL} from "os";
import {default as getstdin} from "get-stdin";
const {Resolver} = require("dns").promises;
import {get as axiosGet} from "axios";
import {default as YAML} from "js-yaml";

import {isHostnameOrphanedDelegation, readFileContentsIntoArray, isHostnameOrphaned} from "../lib/sub-domain-scanner-lib.js"; // NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

const hostnamesFileOpt = 
{
    alias: ["hostnames-file", "hosts-file", "hf", "f"],
    demandOption: true,
    type: "string", 
    description: "A filename which contains hostnames to test (one file per line). usage: --hostnames-file /path/to/file or --hostnames-file - (to use stdin)"
};

const verboseOpt = 
{
    alias: ["verbose", "v"],
    demandOption: false,
    default: false,
    type: "boolean", 
    description: "Create verbose output (includes all tested hostnames, not only those with vulnerabilties)"
};

const YAMLOpt = 
{
    alias: ["yaml", "yml", "y"],
    demandOption: false,
    default: false,
    type: "boolean", 
    description: "Create YAML formatted output (default is JSON)"
};

let mod = 
{
    // Command name - i.e. sub-domain-scanner <command name> <options>
    command: "test-hostnames",

    // Command description
    desc: "Test hostnames for takeover vulnerabilities",

    // Define command options
    builder: 
    {
        hostnamesFile: hostnamesFileOpt,
        verbose: verboseOpt,
        YAML: YAMLOpt
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

            let vulnerabilities = {};

            for(let hostname of hostnames)
            {
                // We'll create an empty array in the vulnerabilities object which could be helpful in the output to know a hostname has been tested
                vulnerabilities[hostname] = [];

                const isVulnerableDelegation = await isHostnameOrphanedDelegation(hostname, Resolver, axiosGet);
                if(isVulnerableDelegation.vulnerable)
                {
                    vulnerabilities[hostname].push(isVulnerableDelegation);
                }

                const isOrphaned: Object = await isHostnameOrphaned(hostname, Resolver, axiosGet);
                if(isOrphaned.vulnerable)
                {       
                    vulnerabilities[hostname].push(isOrphaned);
                }


                // trim empty entries from vulnerabilities if --verbose != true
                if(vulnerabilities[hostname].length === 0 && argv.verbose === false)
                {
                    delete vulnerabilities[hostname];
                }

// TODO: auto takeover for s3 etc. - do as another cmd e.g. sub-domain-scanner auto-takover <hostname> <vuln type>

// TODO: more checks
            }

            // TODO combined JSON/YAML/<something> output format
            if(Object.keys(vulnerabilities).length)
            {
                if(argv.YAML)
                {
                    const output = YAML.safeDump(vulnerabilities);
                    console.log(output);
                }
                else
                {
                    console.log(JSON.stringify(vulnerabilities, null, 2));
                }
            }
            else
            {
                console.log("no vulnerabilties found");
            }
            process.exit(0);
        }
        catch(e)
        {         
            console.error(e.message);
            process.exit(1);
        }
    }
};

// exports.default = mod;
module.exports = mod;