"use strict";

import {get as axiosGet} from "axios";
import {default as getstdin} from "get-stdin";
import {getDomainNamesFromNameserver} from "../lib/sub-domain-scanner-lib.js"; // NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

const nameserversOpt = 
{
    alias: ["nameservers", "ns"],
    demandOption: true,
    type: "array", 
    description: "An array (of space-separated strings) of nameservers to discover hostnames under. Example: --ns=ns1.example.com ns2.example.com or using stdin: --ns=-"
};

let mod = 
{
    // Command name - i.e. sub-domain-scanner <command name> <options>
    command: "discover-domains",

    // Command description
    desc: "Discover domain names CLI method (via nameservers)",

    // Define command options
    builder: 
    {
        nameservers: nameserversOpt
    },

    // Handler/main function - this is executed when this command is requested
    handler: async (argv) => 
    {
        try
        {
            let nameservers: Array = [];

            if(argv.hostnamesFile === "-") // use stdin
            {
                nameservers = await getstdin();
            }
            else
            {
                nameservers = argv.nameservers;
            }

            let domainsSet = new Set();
            for(let nameserver of nameservers)
            {
                const domainsTmp: Array = await getDomainNamesFromNameserver(nameserver, axiosGet);                
                
                for(let rawDomain of domainsTmp)
                {
                    // NOTE: Due to using the RSS interface (rather than PGSQL), have example.com _and_ *.example.com _does_ make a difference, hence:    
                    domainsSet.add(`${rawDomain}`);
                    domainsSet.add(`*.${rawDomain}`);
                }
            }

            const domainsString: string = Array.from(domainsSet).join(",");
            console.log(domainsString);
            process.exit();
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