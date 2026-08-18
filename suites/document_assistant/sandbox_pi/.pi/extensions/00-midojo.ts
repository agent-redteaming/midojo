// Report the agent's file reads to the midojo control plane so injections
// seeded into /sandbox/workdir files are visible to the reachability check.
//
// `reportTools` records each named tool's result verbatim — it never alters
// what the agent sees. We report `read` (pi's built-in file-read tool) and
// `bash` (so a `cat`-style read is also caught).
//
// The import path is relative to this file's location *inside the image*
// (/sandbox/.pi/extensions/ -> /sandbox/.pi/pi-sdk/src); it does not resolve
// against the repo layout, since the file only ever executes in the sandbox.
import { createMidojoExtension } from "../pi-sdk/src";

export default createMidojoExtension({
	controlPlaneUrl: process.env.MIDOJO_URL || "http://localhost:8080",
	reportTools: ["read", "bash"],
});
