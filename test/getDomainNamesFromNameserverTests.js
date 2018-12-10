"use strict";

import {test} from "ava";
import {getDomainNamesFromNameserver} from "../src/lib/sub-domain-scanner-lib.js";
import {EOL} from "os";

// Data
const hackertargetAPIOutput = 
{
    "goodns1.example.com": `www.example.com`,
    "goodns2.example.com": `example.com${EOL}www.example.org${EOL}www.example.net`,
    "badns1.example.com": "error check your search parameter"
};

// Mocks
function axiosGet(url)
{
    return new Promise((resolve, reject) => 
    {
        const output = 
        {
            data: "",
            status: 0
        };

        switch(url)
        {
            case "https://api.hackertarget.com/findshareddns/?q=goodns1.example.com":
                output.data = hackertargetAPIOutput["goodns1.example.com"];
                output.status = 200;
                break;

            case "https://api.hackertarget.com/findshareddns/?q=goodns2.example.com":
                output.data = hackertargetAPIOutput["goodns2.example.com"];
                output.status = 200;
                break;

            case "https://api.hackertarget.com/findshareddns/?q=badns1.example.com":
                output.data = hackertargetAPIOutput["badns1.example.com"];
                output.status = 200;
                break;
        }

        if(output.status === 200)
        {
            return resolve(output);
        }

        const err = new Error("Some error");
        return reject(err);
    });
}

test("Correct operation, valid input (single domain in output)", async (t) => 
{
    const nameserver = "goodns1.example.com";
    const expectedOutput = hackertargetAPIOutput["goodns1.example.com"].trim().split(EOL);

    const domains: Array = await getDomainNamesFromNameserver(nameserver, axiosGet);

    t.deepEqual(domains, expectedOutput);
});

test("Correct operation, valid input (multiple domains in output)", async (t) => 
{
    const nameserver = "goodns2.example.com";
    const expectedOutput = hackertargetAPIOutput["goodns2.example.com"].trim().split(EOL);

    const domains: Array = await getDomainNamesFromNameserver(nameserver, axiosGet);

    t.deepEqual(domains, expectedOutput);
});

test("Correct operation, invalid input (NS has no records)", async (t) => 
{
    const nameserver = "badns1.example.com";
    const expectedOutput = [];

    const domains: Array = await getDomainNamesFromNameserver(nameserver, axiosGet);

    t.deepEqual(domains, expectedOutput);
});

test("Correct operation, invalid input (API returns non-200)", async (t) => 
{
    const nameserver = "400.example.com";

    try
    {
        await getDomainNamesFromNameserver(nameserver, axiosGet);
    }
    catch(e)
    {
        t.is(e instanceof Error, true, "must reject with an Error");
    }
});