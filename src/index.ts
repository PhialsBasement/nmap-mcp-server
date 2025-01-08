#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Schema definitions for NMAP scanning
const NmapScanSchema = z.object({
    target: z.string(),
    ports: z.string().optional(),  // e.g. "22-80" or "80,443" or null for default
    scanType: z.enum(['quick', 'full', 'version']).default('quick'),
    timing: z.number().min(0).max(5).default(3),  // T0-T5 timing templates
    additionalFlags: z.string().optional()
});

const server = new Server({
    name: "nmap-server",
    version: "0.1.0",
}, {
    capabilities: {
        tools: {},
    },
});

async function runNmapScan(params: z.infer<typeof NmapScanSchema>) {
    const { target, ports, scanType, timing, additionalFlags } = params;
    
    // Build the nmap command with proper flags
    let command = `nmap -T${timing}`;
    
    // Add scan type flags
    switch (scanType) {
        case 'quick':
            command += ' -F';  // Fast scan
            break;
        case 'full':
            command += ' -p-';  // All ports
            break;
        case 'version':
            command += ' -sV';  // Version detection
            break;
    }
    
    // Add port specification if provided
    if (ports) {
        command += ` -p${ports}`;
    }
    
    // Add any additional flags
    if (additionalFlags) {
        command += ` ${additionalFlags}`;
    }
    
    // Add target
    command += ` ${target}`;

    try {
        const { stdout, stderr } = await execAsync(command);
        if (stderr) {
            console.error('Nmap stderr:', stderr);
        }
        return stdout;
    } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        throw new Error(`Nmap scan failed: ${errorMessage}`);
    }
}

// Tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "run_nmap_scan",
                description: "Run an NMAP scan on a target. Supports various scan types and configurations.",
                inputSchema: zodToJsonSchema(NmapScanSchema),
            }
        ],
    };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
        const { name, arguments: args } = request.params;
        
        if (name === "run_nmap_scan") {
            const parsed = NmapScanSchema.safeParse(args);
            if (!parsed.success) {
                throw new Error(`Invalid arguments for run_nmap_scan: ${parsed.error}`);
            }

            const result = await runNmapScan(parsed.data);
            
            return {
                content: [{ 
                    type: "text", 
                    text: result 
                }],
                isError: false,
            };
        }

        throw new Error(`Unknown tool: ${name}`);
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return {
            content: [{ type: "text", text: `Error: ${errorMessage}` }],
            isError: true,
        };
    }
});

// Start server
async function runServer() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("NMAP server running on stdio");
}

runServer().catch((error) => {
    console.error("Fatal error running server:", error);
    process.exit(1);
});