"use strict";

import {test} from "ava";
import {getSANSFromCertificatesArray} from "../src/lib/sub-domain-scanner-lib.js";
import {validCertificatesArray1} from "./fixtures/certificatesArray.js";

test("Correct operation, valid input", (t) => 
{
    const expectedOutput = 
    [
        "www.thedotproduct.org"
    ];

    const SANS: Array = getSANSFromCertificatesArray(validCertificatesArray1);
    
    t.deepEqual(SANS, expectedOutput, "SANS must contain only expected values");
});


test("Correct operation, invalid (empty) input", (t) => 
{
    const certificates = [];
    const expectedOutput = [];

    const SANS: Array = getSANSFromCertificatesArray(certificates);
    
    t.deepEqual(SANS, expectedOutput, "SANS must be an empty Array");
});


test("Correct operation, invalid (mangled format) input", (t) => 
{
    const certificates = ["aaaa", "bbb", 2];
    const expectedOutput = [];

    const SANS: Array = getSANSFromCertificatesArray(certificates);
    
    t.deepEqual(SANS, expectedOutput, "SANS must be an empty Array");
});