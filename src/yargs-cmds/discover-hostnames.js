"use strict";

import {EOL} from "os";
import {default as getstdin} from "get-stdin";
import {getHostnamesFromCTLogs, filterHostnames} from "../lib/sub-domain-scanner-lib.js"; // NOTE: Path is relative to build dir (dist/) - local because lib is babel'd


const domainNamesOpt = 
{
    alias: ["domain-names", "domains", "dn"],
    demandOption: true,
    type: "array", 
    description: "An Array of (strings) domain names to use as the seed. Example: --dn=hostname1,hostname 2"
};

const mustMatchOpt = 
{
    alias: ["must-match", "mm"],
    demandOption: false,
    type: "string", 
    default: ".*",
    description: "A regular expression which hostnames must match to be included in the output"
};

const mustNotMatchOpt = 
{
    alias: ["must-not-match", "mnm"],
    demandOption: false,
    type: "string", 
    default: "^$",
    description: "A regular expression which hostnames must not match to be included in the output"
};

const bruteforceOpt = 
{
    alias: ["bruteforce", "bf", "b"],
    demandOption: false,
    type: "boolean", 
    default: false,
    description: "Whether (true) or not (false) to include a list of common sub-domain prefixes on each hostname"
};

/*
args to add:
    --include-ct-logs boolean (true)
    --ignore-expired-certs boolean (false)

    --include-web-crawl boolean (true)
    --web-crawl-depth int (1)
*/

let mod = 
{
    // Command name - i.e. sub-domain-scanner <command name> <options>
    command: "discover-hostnames",

    // Command description
    desc: "Discover hostnames from sources (CT logs, web pages - as per chosen options)",

    // Define command options
    builder: 
    {
        domainNames: domainNamesOpt,
        mustMatch: mustMatchOpt,
        mustNotMatch: mustNotMatchOpt,
        bruteforce: bruteforceOpt
    },

    // Handler/main function - this is executed when this command is requested
    handler: async (argv) => 
    {
        try
        {
            let allHostnames = new Set();

            let domainNames: Array = [];

            if(argv.domainNames[0] === "-") // use stdin
            {
                const stdin  = await getstdin();
                domainNames = stdin.trim().replace(/\ {2,}/g, " ").replace(/\ /g, ",").split(",");
            }
            else
            {
                domainNames = argv.domainNames;
            }

            for(let domainName of domainNames)
            {
                const hostnames: Array = await getHostnamesFromCTLogs(domainName, argv.bruteforce);

                for(let hostname of hostnames)
                {
                    allHostnames.add(hostname);
                }
            }

            const mustMatch: RegExp = new RegExp(argv.mustMatch);
            const mustNotMatch: RegExp = new RegExp(argv.mustNotMatch);

            const dedupedHostnames = Array.from(allHostnames);
            const filteredHostnames = filterHostnames(dedupedHostnames, mustMatch, mustNotMatch);
            const output = filteredHostnames.join(EOL);

            console.log(output);
            process.exit(0);
        }
        catch(e)
        {
            console.error(e.message);
            process.exit(1);
        }
    }
};

module.exports = mod;