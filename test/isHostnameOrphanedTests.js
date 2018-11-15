"use strict";

import {test} from "ava";
import {isHostnameOrphaned} from "../src/lib/sub-domain-scanner-lib.js";

// Mocks
function Resolver()
{
}
Resolver.prototype = 
{
    resolveCname: (hostname: string) => 
    {
        let output: Array = [];

        switch(hostname)
        {
            case "vulnerable-s3.example.com":
                output = ["vulnerable1-af.s3-some-region.amazonaws.com"];
                break;

            case "not-vulnerable-s3.example.com":
                output = ["not-vulnerable.s3-some-region.amazonaws.com"];
                break;
        }

        return output;
    }
};

// NOTE: we're not using the options arg here (yet)
function axiosGet(url)
{
    const output = 
    {
        data: "",
        status: 0
    };

    switch(url)
    {
        case "https://vulnerable1-af.s3-some-region.amazonaws.com/":
            output.data = `<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message><BucketName>vulnerable-s3-bucket-nsc</BucketName><RequestId>140A6363C75597BA</RequestId><HostId>cqDTh/l2DbHcP1O3NapS+uug/aWBed0plEYuhG7iCiNnH0k4dj3RDJYuwKi6etkRoB1uFgRFQnM=</HostId></Error>`;
            output.status = 404;
            break;

        case "https://not-vulnerable.s3-some-region.amazonaws.com/":
            output.data = `Everything is bon`;
            output.status = 200;
            break;
    }

    return new Promise((resolve, reject) => 
    {
        return resolve(output);
    });
}

test("Correct operation, valid input (vulnerable-s3.example.com: vulnerable)", async (t) => 
{
    const hostname = "vulnerable-s3.example.com";

    const output: Object = await isHostnameOrphaned(hostname, Resolver, axiosGet);
    
    t.is(output.vulnerable, true, "vulnerable-s3.example.com must be marked as vulnerable");
    t.is(output.message.indexOf(hostname) >= 0, true, "vulnerable-s3.example.com must appear in the output message");
});

test("Correct operation, valid input (not-vulnerable-s3.example.com: not vulnerable)", async (t) => 
{
    const hostname = "not-vulnerable-s3.example.com";

    const output: Object = await isHostnameOrphaned(hostname, Resolver, axiosGet);
    
    t.is(output.vulnerable, false, "not-vulnerable-s3.example.com must not be marked as vulnerable");
    t.is(output.message.length === 0, true, "output message must be empty");
    t.is(typeof output.message === "string", true, "output message must be a string");
});