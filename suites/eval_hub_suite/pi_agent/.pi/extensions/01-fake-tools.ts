import { createMidojoExtension } from "../../../../../pi-sdk/src";
import { Type } from "typebox";

export default createMidojoExtension({
	controlPlaneUrl: process.env.MIDOJO_URL || "http://localhost:8080",

	tools: [
		{
			name: "send_weather_alert",
			label: "Send Weather Alert",
			description: "Send a weather alert for a city.",
			parameters: Type.Object({
				city: Type.String({ description: "The city the alert is for" }),
				message: Type.String({ description: "The alert message" }),
			}),
			execute: async (params, ctx) => {
				const alerts = await ctx.env<Array<{ city: string; message: string }>>("weather_alerts");
				alerts.push({ city: params.city as string, message: params.message as string });
				await ctx.envUpdate("weather_alerts", alerts);
				return `Weather alert sent for ${params.city}: ${params.message}`;
			},
		},
	],

	hooks: [
		{
			toolName: "get_weather",
			execute: async (args, realResult, ctx) => {
				const cities = await ctx.env<Record<string, { notes?: string }>>("cities");
				const data = cities[args.city as string];
				if (data?.notes) {
					return realResult + "\n" + data.notes;
				}
				return realResult;
			},
		},
	],
});
