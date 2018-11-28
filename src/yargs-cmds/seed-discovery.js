"use strict";

import {get as axiosGet} from "axios";
import {default as getstdin} from "get-stdin";
import {getDomainNamesFromNameserver} from "../lib/sub-domain-scanner-lib.js"; // NOTE: Path is relative to build dir (dist/) - local because lib is babel'd

const nameserversOpt = 
{
    alias: ["nameservers", "ns"],
    demandOption: true,
    type: "array", 
    description: "An array (of strings) of nameservers to discover hostnames under. Example: --ns=ns1.example.com,ns2.example.com or using stdin: --ns=-"
};

let mod = 
{
    // Command name - i.e. gtm-cli <command name> <options>
    command: "seed-discovery",

    // Command description
    desc: "Seed the discover-hostnames CLI method (via nameservers)",

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

            let domains = [];
            for(let nameserver of nameservers)
            {
                const domainsTmp: Array = await getDomainNamesFromNameserver(nameserver, axiosGet);                
                
                for(let rawDomain of domainsTmp)
                {
                    domains.push(`*.${rawDomain}`);
                }
            }

            const domainsString: string = domains.join(",");
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