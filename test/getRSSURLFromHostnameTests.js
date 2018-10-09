"use strict";

import {test} from "ava";
import {getRSSURLFromHostname} from "../src/lib/sub-domain-scanner-lib.js";
import {default as config} from "../config/sub-domain-scanner-config.js";

test("Correct operation, valid (non-wildcard) input", (t) => 
{
    const hostname: string = "www.example.com";
    const expectedOutput: string = `${config.crtshRSSURLPrefix}www.example.com`;

    const res = getRSSURLFromHostname(hostname);

console.log(res);    

    t.is(res === expectedOutput, true, "output must be correct");
});

test("Correct operation, valid (with wildcard) input", (t) => 
{
    const hostname: string = "*.example.com";
    const expectedOutput: string = `${config.crtshRSSURLPrefix}%25.example.com`;

    const res = getRSSURLFromHostname(hostname);

    t.is(res === expectedOutput, true, "output must be correct");
});