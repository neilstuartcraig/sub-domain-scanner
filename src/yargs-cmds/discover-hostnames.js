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

/*
args to add:
    --include-ct-logs boolean (true)
    --ignore-expired-certs boolean (false)

    --include-web-crawl boolean (true)
    --web-crawl-depth int (1)
*/

let mod = 
{
    // Command name - i.e. gtm-cli <command name> <options>
    command: "discover-hostnames",

    // Command description
    desc: "Discover hostnames from sources (CT logs, web pages - as per chosen options)",

    // Define command options
    builder: 
    {
        domainNames: domainNamesOpt,
        mustMatch: mustMatchOpt,
        mustNotMatch: mustNotMatchOpt
    },

    // Handler/main function - this is executed when this command is requested
    handler: async (argv) => 
    {
        try
        {
            let allHostnames = [];

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

            for(let hostname of domainNames)
            {
                const hostnames = await getHostnamesFromCTLogs(hostname);
                allHostnames = allHostnames.concat(hostnames);
            }
            
            const mustMatch: RegExp = new RegExp(argv.mustMatch);
            const mustNotMatch: RegExp = new RegExp(argv.mustNotMatch);

            const filteredHostnames = filterHostnames(allHostnames, mustMatch, mustNotMatch);
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

// exports.default = mod;
module.exports = mod;