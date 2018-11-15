"use strict";

import {join as joinPath} from "path";
import {test} from "ava";
import {readFileContentsIntoArray} from "../src/lib/sub-domain-scanner-lib.js";

test("Correct operation, valid input (4 entries)", async (t) => 
{
    const filename: string = joinPath(__dirname, "/fixtures/readFileContentsIntoArray-valid1.txt");
    const expectedOutput: Array = 
    [
        "www.example.com",
        "example.com",
        "example.org",
        "www.example.co.uk"
    ];

    const output: Array = await readFileContentsIntoArray(filename);
    
    t.deepEqual(output, expectedOutput, "expected output must be correct");
});

test("Correct operation, valid input (1 entry)", async (t) => 
{
    const filename: string = joinPath(__dirname, "/fixtures/readFileContentsIntoArray-valid2.txt");
    const expectedOutput: Array = 
    [
        "sub.example.net"
    ];

    const output: Array = await readFileContentsIntoArray(filename);
    
    t.deepEqual(output, expectedOutput, "expected output must be correct");
});

test("Correct operation, valid input (empty)", async (t) => 
{
    const filename: string = joinPath(__dirname, "fixtures/readFileContentsIntoArray-empty.txt");
    const expectedOutput: Array = [];

    const output: Array = await readFileContentsIntoArray(filename);
    
    t.deepEqual(output, expectedOutput, "expected output must be empty array");
});

test("Correct operation, invalid input (non-existent file)", async (t) => 
{
    const filename: string = joinPath(__dirname, "fixtures/this-file-doesnt-exists.txt");
    
    try
    {
        await readFileContentsIntoArray(filename);
    }
    catch(e)
    {
        t.is(e instanceof Error, true, "must reject the promise, with an error");
    }
});