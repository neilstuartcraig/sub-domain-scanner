"use strict";

import {test} from "ava";
import {getCertificatesFromRSSItems} from "../src/lib/sub-domain-scanner-lib.js";
import {validRSSItems, invalidFormatRSSItems1, invalidFormatRSSItems2} from "./fixtures/RSSItems.js";

test("Correct operation, valid input", async (t) => 
{
    const certificates: Array = getCertificatesFromRSSItems(validRSSItems);
    t.is(certificates.length === validRSSItems.length, true);
    for(let certificate of certificates)
    {
        const m = certificate.match(/-----BEGIN CERTIFICATE-----[^]+-----END CERTIFICATE-----/);
        t.is(typeof m == "object" && m != null, true);
    }
});

test("Correct operation, invalid format input 1", async (t) => 
{
    const certificates: Array = getCertificatesFromRSSItems(invalidFormatRSSItems1);
    t.is(certificates.length === invalidFormatRSSItems1.length - 1, true);
});

test("Correct operation, invalid format input 2", async (t) => 
{
    const certificates: Array = getCertificatesFromRSSItems(invalidFormatRSSItems2);
    t.is(certificates.length === 0, true);
});

test("Correct operation, empty input", async (t) => 
{
    const certificates: Array = getCertificatesFromRSSItems([]);
    t.is(certificates.length === 0, true);
});