import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

function requiredEnv(name: string): string {
  const v = process.env[name]?.trim();
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

const BASE_URL = requiredEnv("VAULT_API_BASE_URL").replace(/\/$/, "");
const JWT = requiredEnv("VAULT_API_JWT");

async function vaultFetch(path: string, options: RequestInit = {}): Promise<unknown> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${JWT}`,
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
  const body = await res.json();
  if (!res.ok) {
    const err = (body as { error?: string }).error ?? res.statusText;
    throw new Error(`vault-api ${res.status}: ${err}`);
  }
  return body;
}

const server = new Server(
  { name: "obsidian-vault-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "list_notes",
      description: "List all markdown notes in the vault, optionally filtered to a subfolder.",
      inputSchema: {
        type: "object",
        properties: {
          prefix: {
            type: "string",
            description: "Relative subfolder path within the vault (e.g. 'World/NPCs'). Omit to list all notes.",
          },
        },
      },
    },
    {
      name: "get_note",
      description: "Read the full content of a single markdown note by its vault-relative path.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Vault-relative path to the note (e.g. 'World/NPCs/Thalindra.md').",
          },
        },
        required: ["path"],
      },
    },
    {
      name: "batch_get_notes",
      description: "Read the content of multiple notes at once (max 50).",
      inputSchema: {
        type: "object",
        properties: {
          paths: {
            type: "array",
            items: { type: "string" },
            description: "Array of vault-relative note paths.",
          },
        },
        required: ["paths"],
      },
    },
    {
      name: "search_notes",
      description: "Full-text search across all notes in the vault.",
      inputSchema: {
        type: "object",
        properties: {
          q: {
            type: "string",
            description: "Search query string.",
          },
          limit: {
            type: "integer",
            description: "Max number of results to return (1-200, default 50).",
            minimum: 1,
            maximum: 200,
          },
        },
        required: ["q"],
      },
    },
    {
      name: "create_note",
      description: "Write a note directly into the vault. Only works for paths under an approved folder (e.g. Sessions/). Use draft_note for everything else.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Vault-relative path for the note (e.g. 'Sessions/Session01.md'). Must be under an approved write folder.",
          },
          content: {
            type: "string",
            description: "Full markdown content of the note.",
          },
        },
        required: ["path", "content"],
      },
    },
    {
      name: "draft_note",
      description: "Write a note to the staging folder for review before it enters the vault. The path will be prefixed with _Staging/ automatically.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Desired vault-relative path (e.g. 'World/NPCs/NewNPC.md'). Will be saved as _Staging/World/NPCs/NewNPC.md.",
          },
          content: {
            type: "string",
            description: "Full markdown content of the note.",
          },
        },
        required: ["path", "content"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;

  try {
    switch (name) {
      case "list_notes": {
        const prefix = (args.prefix as string | undefined) ?? "";
        const qs = prefix ? `?prefix=${encodeURIComponent(prefix)}` : "";
        const data = await vaultFetch(`/v1/notes${qs}`);
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "get_note": {
        const path = args.path as string;
        const data = await vaultFetch(`/v1/note?path=${encodeURIComponent(path)}`);
        const { content } = data as { content: string };
        return { content: [{ type: "text", text: content }] };
      }

      case "batch_get_notes": {
        const paths = args.paths as string[];
        const data = await vaultFetch("/v1/notes/batch", {
          method: "POST",
          body: JSON.stringify({ paths }),
        });
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "search_notes": {
        const q = args.q as string;
        const limit = (args.limit as number | undefined) ?? 50;
        const data = await vaultFetch(
          `/v1/search?q=${encodeURIComponent(q)}&limit=${limit}`
        );
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "create_note": {
        const path = args.path as string;
        const content = args.content as string;
        const data = await vaultFetch("/v1/note", {
          method: "PUT",
          body: JSON.stringify({ path, content }),
        });
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      case "draft_note": {
        const path = args.path as string;
        const content = args.content as string;
        const data = await vaultFetch("/v1/draft", {
          method: "PUT",
          body: JSON.stringify({ path, content }),
        });
        return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { content: [{ type: "text", text: `Error: ${msg}` }], isError: true };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
