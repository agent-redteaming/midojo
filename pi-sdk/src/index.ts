import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import type { TSchema } from "typebox";

export interface ToolContext {
	env<T = unknown>(field: string): Promise<T>;
	envUpdate(field: string, value: unknown): Promise<void>;
}

export interface MidojoToolDef {
	name: string;
	label: string;
	description: string;
	parameters: TSchema;
	execute: (params: Record<string, unknown>, ctx: ToolContext) => Promise<string>;
}

export interface MidojoToolHook {
	toolName: string;
	execute: (
		args: Record<string, unknown>,
		realResult: string,
		ctx: ToolContext,
	) => Promise<string>;
}

export interface MidojoExtensionConfig {
	controlPlaneUrl: string;
	tools?: MidojoToolDef[];
	hooks?: MidojoToolHook[];
	/**
	 * Names of existing tools whose results are reported to the control plane
	 * verbatim. Unlike `hooks`, a reporter never rewrites the result the agent
	 * sees — it taps the output, records it, and leaves it untouched. Use this to
	 * make a tool's result (e.g. a file `read`) visible to midojo's reachability
	 * check without perturbing the agent. Names already handled by `hooks` are
	 * skipped so a tool is never recorded twice.
	 */
	reportTools?: string[];
}

class ControlPlaneClient {
	private baseUrl: string;

	constructor(baseUrl: string) {
		const base = baseUrl.replace(/\/+$/, "");
		this.baseUrl = `${base}/current`;
	}

	async getEnvironment(): Promise<Record<string, unknown>> {
		const resp = await fetch(`${this.baseUrl}/environment`);
		if (!resp.ok) return {};
		return (await resp.json()) as Record<string, unknown>;
	}

	async putEnvironment(env: Record<string, unknown>): Promise<void> {
		await fetch(`${this.baseUrl}/environment`, {
			method: "PUT",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(env),
		});
	}

	async recordFunctionCall(entry: { function: string; args: Record<string, unknown>; result: string; error?: string | null }): Promise<void> {
		await fetch(`${this.baseUrl}/function-calls`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(entry),
		}).catch(() => {});
	}

	createToolContext(): ToolContext {
		return {
			env: async <T = unknown>(field: string): Promise<T> => {
				const env = await this.getEnvironment();
				return env[field] as T;
			},
			envUpdate: async (field: string, value: unknown): Promise<void> => {
				const env = await this.getEnvironment();
				env[field] = value;
				await this.putEnvironment(env);
			},
		};
	}
}

export function createMidojoExtension(config: MidojoExtensionConfig): (pi: ExtensionAPI) => void {
	return (pi: ExtensionAPI) => {
		const client = new ControlPlaneClient(config.controlPlaneUrl);

		for (const toolDef of config.tools ?? []) {
			pi.registerTool({
				name: toolDef.name,
				label: toolDef.label,
				description: toolDef.description,
				parameters: toolDef.parameters,
				async execute(_toolCallId, params) {
					const typedParams = params as Record<string, unknown>;
					const ctx = client.createToolContext();

					let result: string;
					let error: string | null = null;
					try {
						result = await toolDef.execute(typedParams, ctx);
					} catch (e) {
						error = e instanceof Error ? e.message : String(e);
						result = error;
					}

					await client.recordFunctionCall({
						function: toolDef.name,
						args: typedParams,
						result,
						error,
					});

					return {
						content: [{ type: "text" as const, text: result }],
						details: { tool: toolDef.name, params: typedParams },
					};
				},
			});
		}

		for (const hook of config.hooks ?? []) {
			pi.on("tool_result", async (event) => {
				if (event.toolName !== hook.toolName) return;

				const ctx = client.createToolContext();
				const realResult = event.content
					.filter((c): c is { type: "text"; text: string } => c.type === "text")
					.map((c) => c.text)
					.join("\n");

				let result: string;
				let error: string | null = null;
				try {
					result = await hook.execute(event.input, realResult, ctx);
				} catch (e) {
					error = e instanceof Error ? e.message : String(e);
					result = error;
				}

				await client.recordFunctionCall({
					function: hook.toolName,
					args: event.input,
					result,
					error,
				});

				return {
					content: [{ type: "text" as const, text: result }],
				};
			});
		}

		// Passive reporters: record a tool's result to the control plane without
		// altering it. Skips any name already covered by `hooks` above so a tool
		// is never recorded twice.
		const hookedTools = new Set((config.hooks ?? []).map((h) => h.toolName));
		for (const reportToolName of new Set(config.reportTools ?? [])) {
			if (hookedTools.has(reportToolName)) continue;
			pi.on("tool_result", async (event) => {
				if (event.toolName !== reportToolName) return;

				const result = event.content
					.filter((c): c is { type: "text"; text: string } => c.type === "text")
					.map((c) => c.text)
					.join("\n");

				await client.recordFunctionCall({
					function: reportToolName,
					args: event.input,
					result,
					error: null,
				});
				// No return value: leave the tool result untouched so the agent
				// sees the real output — this observes, it does not mutate.
			});
		}
	};
}
