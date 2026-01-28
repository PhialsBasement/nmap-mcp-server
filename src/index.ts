#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

// Whitelist of allowed nmap flags for security  
const ALLOWED_FLAGS = [  
    '-sS', '-sT', '-sA', '-sW', '-sM', '-sU', '-sN', '-sF', '-sX',  
    '-O', '-sV', '-sC', '-F', '-p-', '-v', '--open', '--reason',  
    '-Pn', '-PP', '-PM', '-PO', '-PE', '-PS', '-PA', '-PU', '-PY',  
    '-6', '-4', '-b', '-D', '-S', '-e', '-g', '-f', '-i', '-M', '-o',  
    '-R', '-r', '-T', '-V'  
];  
  
// Validate additionalFlags for security to prevent command injection  
function validateAdditionalFlags(flags: string): boolean {  
    if (!flags || typeof flags !== 'string') {  
        return false;  
    }  
      
    // Split flags and filter empty strings  
    const flagArray = flags.split(' ').filter(f => f.trim());  
      
    // Check each flag against whitelist and dangerous characters  
    return flagArray.every(flag => {  
        // Check if it's an allowed single flag  
        if (ALLOWED_FLAGS.includes(flag)) {  
            return true;  
        }  
          
        // Check if it's a safe parameterized flag  
        if (flag.startsWith('--script=') && flag.length > 9) {  
            return true; // Allow --script parameter  
        }  
          
        if (flag.startsWith('-p') && flag.length > 2) {  
            return true; // Allow -p parameter  
        }  
          
        if (flag.startsWith('-d') && /^\d+$/.test(flag.slice(2))) {  
            return true; // Allow debug level  
        }  
          
        // Check for dangerous characters that could enable injection  
        const dangerousChars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'"];  
        return !dangerousChars.some(char => flag.includes(char));  
    });  
}

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
      
    // Build arguments array instead of command string for security  
    const args = [`-T${timing}`];  
      
    // Add scan type flags  
    switch (scanType) {  
        case 'quick':  
            args.push('-F');  // Fast scan  
            break;  
        case 'full':  
            args.push('-p-');  // All ports  
            break;  
        case 'version':  
            args.push('-sV');  // Version detection  
            break;  
    }  
      
    // Add port specification if provided  
    if (ports) {  
        args.push('-p', ports);  
    }  
      
    // Validate and add additional flags with security check  
    if (additionalFlags) {  
        if (!validateAdditionalFlags(additionalFlags)) {  
            throw new Error('Invalid or dangerous additional flags detected');  
        }  
        args.push(...additionalFlags.split(' ').filter(f => f.trim()));  
    }  
      
    // Add target as last argument  
    args.push(target);  
  
    try {  
        // Use execFile instead of exec to prevent shell injection  
        const { stdout, stderr } = await execFileAsync('nmap', args);  
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
