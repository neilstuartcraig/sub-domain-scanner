"use strict";

import {test} from "ava";
import {filterHostnames} from "../src/lib/sub-domain-scanner-lib.js";

const hostnames = ["example.com", "a.example.com", "b.example.com", "c.d.example.com", "example.net", "a.example.net", "b.example.net", "c.d.example.net", "example"];

test("Correct operation, valid input (no matching)", (t) => 
{
    const mustMatch = /.*/;
    const mustNotMatch = /^$/;

    const expectedOutput = hostnames;

    const filteredHostnames = filterHostnames(hostnames, mustMatch, mustNotMatch);

    t.deepEqual(filteredHostnames, expectedOutput, "Output must be same as input");
});

test("Correct operation, valid input (must match *example.com)", (t) => 
{
    const mustMatch = /example\.com$/;
    const mustNotMatch = /^$/;

    const expectedOutput = ["example.com", "a.example.com", "b.example.com", "c.d.example.com"];

    const filteredHostnames = filterHostnames(hostnames, mustMatch, mustNotMatch);

    t.deepEqual(filteredHostnames, expectedOutput, "Output must include only *example.com");
});

test("Correct operation, valid input (must match *.example.com but not example.com)", (t) => 
{
    const mustMatch = /\.example\.com$/;
    const mustNotMatch = /^example.com$/;

    const expectedOutput = ["a.example.com", "b.example.com", "c.d.example.com"];

    const filteredHostnames = filterHostnames(hostnames, mustMatch, mustNotMatch);

    t.deepEqual(filteredHostnames, expectedOutput, "Output must match only *.example.com");
});

test("Correct operation, valid input (must not match example.com)", (t) => 
{
    const mustMatch = /.*/;
    const mustNotMatch = /^example.com$/;

    const expectedOutput = ["a.example.com", "b.example.com", "c.d.example.com", "example.net", "a.example.net", "b.example.net", "c.d.example.net", "example"];

    const filteredHostnames = filterHostnames(hostnames, mustMatch, mustNotMatch);

    t.deepEqual(filteredHostnames, expectedOutput, "Output must match everything except example.com");
});

test("Correct operation, valid input (must only match example.com and example.net)", (t) => 
{
    const mustMatch = /^example.(?:com|net)$/;
    const mustNotMatch = /^$/;

    const expectedOutput = ["example.com", "example.net"];

    const filteredHostnames = filterHostnames(hostnames, mustMatch, mustNotMatch);

    t.deepEqual(filteredHostnames, expectedOutput, "Output must match everything only example.com and example.net");
});

test("Correct operation, valid input (must not match example.com and example.net)", (t) => 
{
    const mustMatch = /.*/;
    const mustNotMatch = /^example.(com|net)$/;

    const expectedOutput = ["a.example.com", "b.example.com", "c.d.example.com", "a.example.net", "b.example.net", "c.d.example.net", "example"];

    const filteredHostnames = filterHostnames(hostnames, mustMatch, mustNotMatch);

    t.deepEqual(filteredHostnames, expectedOutput, "Output must match everything except example.com");
});
