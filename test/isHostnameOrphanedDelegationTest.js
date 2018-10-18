"use strict";

import {test} from "ava";
import {isHostnameOrphanedDelegation} from "../src/lib/sub-domain-scanner-lib.js";

test("Correct operation, valid input (not vulnerable)", async (t) => 
{
    const hostname = "thedotproduct.org";

    const isOrphaned: Object = await isHostnameOrphanedDelegation(hostname);
    
    t.is(isOrphaned.vulnerable, false, "must not be marked as vulnerable");
    t.is(isOrphaned.reasonCode, "HOSTNAME_NOT_DELEGATED", "reasonCode must be HOSTNAME_NOT_DELEGATED");
});

test("Correct operation, valid input (vulnerable, local)", async (t) => 
{
    const hostname = "ns-not-exists-local.thedotproduct.org";

    const isOrphaned: Object = await isHostnameOrphanedDelegation(hostname);
    
    t.is(isOrphaned.vulnerable, true, "must be marked as vulnerable");
    t.is(isOrphaned.reasonCode, "NS_DOESNT_RESOLVE", "reasonCode must be NS_DOESNT_RESOLVE");
});

test("Correct operation, valid input (vulnerable, remote)", async (t) => 
{
    const hostname = "ns-not-exists-remote.thedotproduct.org";

    const isOrphaned: Object = await isHostnameOrphanedDelegation(hostname);
    
    t.is(isOrphaned.vulnerable, true, "must be marked as vulnerable");
    t.is(isOrphaned.reasonCode, "NS_DOESNT_RESOLVE", "reasonCode must be NS_DOESNT_RESOLVE");
});

test("Correct operation, valid input (not delegated)", async (t) => 
{
    const hostname = "www.thedotproduct.org";

    const isOrphaned: Object = await isHostnameOrphanedDelegation(hostname);
 
    t.is(isOrphaned.vulnerable, false, "must not be marked as vulnerable");
    t.is(isOrphaned.reasonCode, "HOSTNAME_NOT_DELEGATED", "reasonCode must be HOSTNAME_NOT_DELEGATED");
});

test("Correct operation, invalid input (NXDOMAIN on hostname)", async (t) => 
{
    const hostname = "www.theresnowaythisdomainwilleverexistinthewholeworld.tldwhichdoesntexist";

    const isOrphaned: Object = await isHostnameOrphanedDelegation(hostname);

    t.is(isOrphaned.vulnerable, false, "must not be marked as vulnerable");
    t.is(isOrphaned.reasonCode, "HOSTNAME_NOT_DELEGATED", "reasonCode must be HOSTNAME_NOT_DELEGATED");
});

test("Correct operation, invalid input (orphaned/BBCx2)", async (t) => 
{
    const hostname = "beeb.thedotproduct.org";

    const isOrphaned: Object = await isHostnameOrphanedDelegation(hostname);

    t.is(isOrphaned.vulnerable, true, "must be marked as vulnerable");
    t.is(isOrphaned.reasonCode, "NS_HAS_NO_RECORDS", "reasonCode must be NS_HAS_NO_RECORDS");
});

test("Correct operation, invalid input (NS is an IP address)", async (t) => 
{
    // NOTE: whilst this is potentially vulnerable to SDT, it's not vulnerable as an orphaned delegation
    const hostname = "ns-is-ip-not-an-ns.thedotproduct.org";

    const isOrphaned: Object = await isHostnameOrphanedDelegation(hostname);

    t.is(isOrphaned.vulnerable, true, "must be marked as vulnerable");
    t.is(isOrphaned.reasonCode, "IP_NS_DOESNT_RESOLVE", "reasonCode must be IP_NS_DOESNT_RESOLVE");
});