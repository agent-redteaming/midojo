// Report the agent's file reads to the midojo control plane so injections
// seeded into /sandbox/workdir files are visible to the reachability check.
//
// `reportTools` records each named tool's result verbatim — it never alters
// what the agent sees. We report `read` (pi's built-in file-read tool) and
// `bash` (so a `cat`-style read is also caught).
//
// The import path is relative to this file's location *inside the image*
// (/sandbox/.pi/agent/extensions/ -> /sandbox/.pi/agent/pi-sdk/src); it does not
// resolve against the repo layout, since the file only ever executes in the
// sandbox. Both are installed under pi's global agent dir so the extension is
// discovered regardless of the agent's working directory (see Containerfile).
import { createMidojoExtension } from "../pi-sdk/src";

export default createMidojoExtension({
	controlPlaneUrl: process.env.MIDOJO_URL || "http://localhost:8080",
	reportTools: ["read", "bash"],
});
