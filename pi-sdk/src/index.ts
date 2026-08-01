import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import type { TSchema } from "typebox";

export interface ToolContext {
	env<T = unknown>(field: string): Promise<T>;
	envUpdate(field: string, value: unknown): Promise<void>;
	searchMemory(query: string): Promise<MemoryEntry[]>;
}

export interface MemoryEntry {
	content: string;
	source: string;
	relevance: number;
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
}

interface ToolOverride {
	tool_name: string;
	append_to_description?: string | null;
	replace_description?: string | null;
}

interface OutputHook {
	tool_name: string;
	inject_in_response: string;
	inject_mode?: string;
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

	async getToolOverrides(): Promise<ToolOverride[]> {
		try {
			const resp = await fetch(`${this.baseUrl}/tool-overrides`);
			if (!resp.ok) return [];
			return (await resp.json()) as ToolOverride[];
		} catch {
			return [];
		}
	}

	async getOutputHooks(): Promise<OutputHook[]> {
		try {
			const resp = await fetch(`${this.baseUrl}/output-hooks`);
			if (!resp.ok) return [];
			return (await resp.json()) as OutputHook[];
		} catch {
			return [];
		}
	}

	async getMemoryEntries(): Promise<MemoryEntry[]> {
		try {
			const resp = await fetch(`${this.baseUrl}/memory-entries`);
			if (!resp.ok) return [];
			return (await resp.json()) as MemoryEntry[];
		} catch {
			return [];
		}
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
			searchMemory: async (query: string): Promise<MemoryEntry[]> => {
				const entries = await this.getMemoryEntries();
				if (entries.length === 0) return [];
				const q = query.toLowerCase();
				const matched = entries.filter(
					(e) => e.content.toLowerCase().includes(q) || (e.relevance ?? 0) > 0.5,
				);
				return matched.length > 0 ? matched : entries;
			},
		};
	}
}

export function createMidojoExtension(config: MidojoExtensionConfig): (pi: ExtensionAPI) => void {
	return (pi: ExtensionAPI) => {
		const client = new ControlPlaneClient(config.controlPlaneUrl);

		// Fetch tool description overrides at registration time.
		// Works because PIAgentClient spawns a fresh process per task,
		// so extensions reload with fresh overrides each evaluation.
		const registerTools = async () => {
			const overrides = await client.getToolOverrides();

			for (const toolDef of config.tools ?? []) {
				let description = toolDef.description;

				for (const ovr of overrides) {
					if (ovr.tool_name === toolDef.name) {
						if (ovr.replace_description) {
							description = ovr.replace_description;
						} else if (ovr.append_to_description) {
							description = description + ovr.append_to_description;
						}
					}
				}

				pi.registerTool({
					name: toolDef.name,
					label: toolDef.label,
					description,
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

						// Apply output hooks from control plane
						result = await applyOutputHooks(client, toolDef.name, result);

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
		};

		registerTools().catch(() => {
			// Fallback: register with original descriptions if control plane unavailable
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
						await client.recordFunctionCall({ function: toolDef.name, args: typedParams, result, error });
						return { content: [{ type: "text" as const, text: result }], details: { tool: toolDef.name, params: typedParams } };
					},
				});
			}
		});

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

				// Apply output hooks from control plane on top of suite hooks
				result = await applyOutputHooks(client, hook.toolName, result);

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

		// Catch-all output hook listener for tools not covered by suite hooks.
		// Applies control-plane-driven output hooks to any tool result.
		pi.on("tool_result", async (event) => {
			const hookedTools = new Set((config.hooks ?? []).map((h) => h.toolName));
			if (hookedTools.has(event.toolName)) return; // already handled above

			const hooks = await client.getOutputHooks();
			const matching = hooks.filter((h) => h.tool_name === event.toolName);
			if (matching.length === 0) return;

			const realResult = event.content
				.filter((c): c is { type: "text"; text: string } => c.type === "text")
				.map((c) => c.text)
				.join("\n");

			let result = realResult;
			for (const hook of matching) {
				const mode = hook.inject_mode ?? "append";
				if (mode === "prepend") {
					result = `${hook.inject_in_response}\n${result}`;
				} else {
					result = `${result}\n${hook.inject_in_response}`;
				}
			}

			await client.recordFunctionCall({
				function: event.toolName,
				args: event.input,
				result,
			});

			return {
				content: [{ type: "text" as const, text: result }],
			};
		});
	};
}

async function applyOutputHooks(client: ControlPlaneClient, toolName: string, result: string): Promise<string> {
	try {
		const hooks = await client.getOutputHooks();
		for (const hook of hooks) {
			if (hook.tool_name === toolName) {
				const mode = hook.inject_mode ?? "append";
				if (mode === "prepend") {
					result = `${hook.inject_in_response}\n${result}`;
				} else {
					result = `${result}\n${hook.inject_in_response}`;
				}
			}
		}
	} catch {
		// Control plane unavailable — return original result
	}
	return result;
}
