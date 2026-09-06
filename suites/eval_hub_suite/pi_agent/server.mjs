// Minimal HTTP wrapper around the `pi` coding agent for the midojo
// `--protocol http` transport (EvalHub Option C).
//
// Contract (matches midojo's SimpleHTTPAgentClient):
//   POST /            body {"prompt": "..."}  -> 200 {"response": "..."}
//   GET  /health                              -> 200 {"status": "ok"}
//
// For each request we launch `pi -p --no-session <prompt>` with cwd set to the
// agent dir and MIDOJO_URL inherited from the environment, mirroring midojo's
// PIAgentClient. The bundled pi-sdk extensions (fake/real tools) then call back
// to the control plane at MIDOJO_URL so the run can be graded.
import http from "node:http";
import { spawn } from "node:child_process";

const HOST = process.env.AGENT_HOST || "0.0.0.0";
const PORT = parseInt(process.env.AGENT_PORT || "8000", 10);
const AGENT_DIR = process.env.AGENT_DIR || process.cwd();
const PI_TIMEOUT_MS = parseInt(process.env.PI_TIMEOUT_MS || "300000", 10);
const MAX_BODY_BYTES = 10 * 1024 * 1024;

function runPi(prompt) {
	return new Promise((resolve, reject) => {
		const child = spawn("pi", ["-p", "--no-session", prompt], {
			cwd: AGENT_DIR,
			env: process.env, // MIDOJO_URL, LITELLM_* inherited from the pod env
			// stdin = /dev/null (immediate EOF): the prompt is passed as an arg, and
			// pi in print mode blocks reading stdin if it is left an open, empty pipe.
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		const timer = setTimeout(() => {
			child.kill("SIGKILL");
			reject(new Error(`pi timed out after ${PI_TIMEOUT_MS}ms`));
		}, PI_TIMEOUT_MS);
		child.stdout.on("data", (d) => {
			stdout += d;
		});
		child.stderr.on("data", (d) => {
			stderr += d;
		});
		child.on("error", (err) => {
			clearTimeout(timer);
			reject(err);
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			if (code !== 0) {
				reject(new Error(`pi exited with code ${code}: ${stderr.slice(-2000)}`));
			} else {
				resolve(stdout.trim());
			}
		});
	});
}

function sendJSON(res, status, obj) {
	const body = JSON.stringify(obj);
	res.writeHead(status, { "content-type": "application/json" });
	res.end(body);
}

const server = http.createServer((req, res) => {
	if (req.method === "GET" && (req.url === "/health" || req.url === "/healthz")) {
		sendJSON(res, 200, { status: "ok" });
		return;
	}
	if (req.method !== "POST") {
		sendJSON(res, 404, { error: "not found" });
		return;
	}

	let body = "";
	let aborted = false;
	req.on("data", (chunk) => {
		body += chunk;
		if (body.length > MAX_BODY_BYTES) {
			aborted = true;
			sendJSON(res, 413, { error: "request body too large" });
			req.destroy();
		}
	});
	req.on("end", async () => {
		if (aborted) return;
		let prompt;
		try {
			prompt = JSON.parse(body).prompt;
		} catch {
			sendJSON(res, 400, { error: "invalid JSON body" });
			return;
		}
		if (typeof prompt !== "string") {
			sendJSON(res, 400, { error: "missing string field 'prompt'" });
			return;
		}
		try {
			const response = await runPi(prompt);
			sendJSON(res, 200, { response });
		} catch (err) {
			console.error("[pi-agent] run failed:", err);
			sendJSON(res, 500, { error: String((err && err.message) || err) });
		}
	});
});

server.listen(PORT, HOST, () => {
	console.log(
		`[pi-agent] listening on ${HOST}:${PORT} | cwd=${AGENT_DIR} | MIDOJO_URL=${process.env.MIDOJO_URL || "(unset)"}`,
	);
});
