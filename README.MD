# MCP NMAP Server

A Model Context Protocol (MCP) server that enables AI assistants to perform network scanning operations using NMAP. This server provides a standardized interface for AI models to interact with NMAP, making it possible to perform network analysis and security assessments through AI conversations.

## Prerequisites

- Windows operating system
- Node.js (v18 or higher)
- NMAP installed and accessible from Windows command line
- TypeScript for development

## Installation

Install the package globally using npm:

```bash
npm install -g mcp-nmap-server
```

Or install locally in your project:

```bash
npm install mcp-nmap-server
```

## Features

The server provides access to NMAP's core functionality through a simple interface. It supports quick scans, full port scans, version detection, and custom timing templates. The implementation uses NMAP's native command-line interface, ensuring reliability and consistency with standard NMAP operations.

## Configuration with Claude Desktop

To use this server with Claude Desktop on Windows, you'll need to configure it in the Claude configuration file located at:
`C:\Users\YOUR_USERNAME\AppData\Roaming\Claude\config.json`

Add the NMAP server to your configuration by adding it to the `mcpServers` section. Here's a complete example of a Claude Desktop configuration file:

```json
{
    "mcpServers": {
        "nmap": {
            "command": "node",
            "args": [
                "C:\\Users\\YOUR_USERNAME\\Downloads\\mcp-nmap-server\\dist\\index.js"
            ]
        }
    },
    "globalShortcut": "Ctrl+Q"
}
```

Replace `YOUR_USERNAME` with your Windows username and adjust the path to where you've installed the NMAP server.

## Usage with AI

Once configured, AI assistants like Claude can use the server through the `run_nmap_scan` function. The function accepts the following parameters:

```typescript
{
    target: string;            // Host or network to scan
    ports?: string;           // Optional port specification (e.g., "80,443" or "1-1000")
    scanType?: 'quick' | 'full' | 'version';  // Scan type (default: 'quick')
    timing?: number;          // NMAP timing template 0-5 (default: 3)
    additionalFlags?: string; // Optional additional NMAP flags
}
```

Example conversation with Claude:

```
Human: Can you scan localhost for open ports?

Claude: I'll help you scan localhost using NMAP.

<runs nmap scan with parameters>
target: "localhost"
scanType: "quick"
timing: 3
```


## License

MIT License

## Support

For issues, suggestions, or contributions, please visit the GitHub repository.