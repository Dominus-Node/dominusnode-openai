# Dominus Node OpenAI-Compatible Function Calling Schemas

OpenAI function-calling schemas and handler implementations for the Dominus Node rotating proxy-as-a-service platform. These schemas allow any LLM with function/tool calling support to interact with Dominus Node's proxy network, wallet, and agentic wallet APIs.

## What This Is

This directory contains:

| File | Description |
|------|-------------|
| `functions.json` | Array of 8 OpenAI function definitions (JSON Schema format) |
| `handler.ts` | TypeScript handler that dispatches function calls to the Dominus Node API |
| `handler.py` | Python handler that dispatches function calls to the Dominus Node API |

The function schemas follow the [OpenAI function calling specification](https://platform.openai.com/docs/guides/function-calling), which has become a de facto standard adopted by Claude (tool_use), Gemini, Mistral, Llama, and others.

## Available Functions

| Function | Description | Auth Required |
|----------|-------------|---------------|
| `dominusnode_proxied_fetch` | Make an HTTP request through Dominus Node's rotating proxy network | Yes |
| `dominusnode_check_balance` | Check wallet balance (cents, USD, currency) | Yes |
| `dominusnode_check_usage` | Check usage stats for a time period (day/week/month) | Yes |
| `dominusnode_get_proxy_config` | Get proxy endpoints, supported countries, geo-targeting info | Yes |
| `dominusnode_list_sessions` | List currently active proxy sessions | Yes |
| `dominusnode_create_agentic_wallet` | Create a sub-wallet for an AI agent with spending limits | Yes |
| `dominusnode_fund_agentic_wallet` | Transfer funds from main wallet to an agentic wallet | Yes |
| `dominusnode_agentic_wallet_balance` | Check an agentic wallet's balance and status | Yes |

## Usage with OpenAI GPT (Function Calling)

```python
import json
import openai
from handler import create_dominusnode_function_handler

# Load function definitions
with open("functions.json") as f:
    functions = json.load(f)

# Create the Dominus Node handler
dominusnode = create_dominusnode_function_handler(
    api_key="dn_live_your_api_key_here",
    base_url="https://api.dominusnode.com",
)

# Create a chat completion with function calling
client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "You have access to Dominus Node proxy tools."},
        {"role": "user", "content": "What is my current proxy balance?"},
    ],
    functions=functions,
    function_call="auto",
)

# Handle function calls from the LLM
message = response.choices[0].message
if message.function_call:
    name = message.function_call.name
    args = json.loads(message.function_call.arguments)

    # Dispatch to Dominus Node handler
    result = await dominusnode(name, args)

    # Send the result back to the LLM
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You have access to Dominus Node proxy tools."},
            {"role": "user", "content": "What is my current proxy balance?"},
            message,
            {"role": "function", "name": name, "content": result},
        ],
    )
    print(response.choices[0].message.content)
```

## Usage with Claude (tool_use)

Claude uses a `tools` parameter with a slightly different schema format. Convert the OpenAI functions to Claude tool format:

```python
import json
import anthropic
from handler import create_dominusnode_function_handler

# Load and convert function definitions to Claude tool format
with open("functions.json") as f:
    functions = json.load(f)

tools = [
    {
        "name": fn["name"],
        "description": fn["description"],
        "input_schema": fn["parameters"],
    }
    for fn in functions
]

# Create the Dominus Node handler
dominusnode = create_dominusnode_function_handler(
    api_key="dn_live_your_api_key_here",
)

# Create a message with tool use
client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    tools=tools,
    messages=[
        {"role": "user", "content": "Check my Dominus Node proxy balance and usage this week."},
    ],
)

# Handle tool use blocks
for block in response.content:
    if block.type == "tool_use":
        result = await dominusnode(block.name, block.input)

        # Send result back
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            tools=tools,
            messages=[
                {"role": "user", "content": "Check my Dominus Node proxy balance and usage this week."},
                {"role": "assistant", "content": response.content},
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        }
                    ],
                },
            ],
        )
        print(response.content[0].text)
```

## Usage with TypeScript / Node.js

```typescript
import { readFileSync } from "fs";
import { createDominusNodeFunctionHandler } from "./handler";

// Load function definitions
const functions = JSON.parse(readFileSync("functions.json", "utf-8"));

// Create the handler
const handler = createDominusNodeFunctionHandler({
  apiKey: "dn_live_your_api_key_here",
  baseUrl: "https://api.dominusnode.com",
});

// Example: direct function call
const balance = await handler("dominusnode_check_balance", {});
console.log(JSON.parse(balance));
// { balanceCents: 5000, balanceUsd: 50.00, currency: "USD", lastToppedUp: "..." }

// Example: proxied fetch with geo-targeting
const fetchResult = await handler("dominusnode_proxied_fetch", {
  url: "https://httpbin.org/ip",
  method: "GET",
  country: "US",
  proxy_type: "residential",
});
console.log(JSON.parse(fetchResult));

// Example: create and fund an agentic wallet for an AI agent
const wallet = await handler("dominusnode_create_agentic_wallet", {
  label: "research-agent-1",
  spending_limit_cents: 500,  // $5.00 per-transaction limit
});
const walletData = JSON.parse(wallet);

await handler("dominusnode_fund_agentic_wallet", {
  wallet_id: walletData.id,
  amount_cents: 2000,  // Fund with $20.00
});
```

## Usage with Any Function-Calling LLM

The `functions.json` file follows the standard OpenAI function definition schema. Most LLM frameworks accept this format directly or with minor adaptation:

### Generic Pattern

1. Load `functions.json` and pass to your LLM as available functions/tools.
2. When the LLM returns a function call, extract the function name and arguments.
3. Pass them to the handler: `result = await handler(name, args)`.
4. Return the result string to the LLM as the function result.

### Framework-Specific Notes

| Framework | How to Use |
|-----------|-----------|
| **OpenAI SDK** | Pass `functions` directly to `chat.completions.create()` |
| **Anthropic SDK** | Convert to `tools` format (rename `parameters` to `input_schema`) |
| **Google Gemini** | Convert to `FunctionDeclaration` objects |
| **LangChain** | Use `StructuredTool.from_function()` or the Dominus Node LangChain integration |
| **Vercel AI SDK** | See the `integrations/vercel-ai/` package |
| **LlamaIndex** | Use `FunctionTool.from_defaults()` with the handler |
| **Ollama** | Pass as `tools` parameter in chat API |

## Security

### SSRF Prevention

Both handlers (TypeScript and Python) include comprehensive SSRF prevention that blocks:

- **Private IP ranges**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 0.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10 (CGNAT)
- **Non-standard IP representations**: Hex (0x7f000001), octal (0177.0.0.1), decimal integer (2130706433)
- **IPv6 private ranges**: ::1, fc00::/7, fe80::/10, ::ffff:-mapped private IPs
- **Internal hostnames**: .localhost, .local, .internal, .arpa TLDs
- **Protocol restriction**: Only http:// and https:// are allowed

### Header Injection Prevention

User-supplied HTTP headers are filtered to block:
- Security-sensitive headers (Host, Authorization, Proxy-Authorization, etc.)
- CRLF injection attempts (headers containing \r or \n)
- Null byte injection

### Sanctioned Countries

Requests targeting OFAC-sanctioned countries (CU, IR, KP, RU, SY) are blocked at the handler level before reaching the proxy.

### Input Validation

- Integer overflow protection: amount/limit values capped at 2,147,483,647
- Label length validation: max 100 characters
- URL-encoding of path parameters to prevent path traversal
- Prototype pollution prevention in JSON parsing (TypeScript handler)
- Response body size limit: 10 MB max to prevent OOM

### API Key Security

- API keys are never included in function call results returned to the LLM
- Authentication tokens are stored in handler closure scope (not exported)
- The handler authenticates lazily on first call and caches the JWT token

## Proxy Pricing

| Proxy Type | Price | Best For |
|------------|-------|----------|
| Datacenter (`dc`) | $3.00/GB | General scraping, speed-critical tasks |
| Residential | $5.00/GB | Anti-detection, geo-restricted content |

## Dependencies

### TypeScript Handler
- Node.js 18+ (uses native `fetch` and `AbortSignal.timeout`)
- No external dependencies

### Python Handler
- Python 3.8+
- `httpx` (`pip install httpx`)

## Related Integrations

- `integrations/langchain/` -- LangChain tools integration
- `integrations/vercel-ai/` -- Vercel AI SDK provider
- `packages/mcp-server/` -- Model Context Protocol server (34 tools)
- `sdks/node/` -- Full Node.js SDK
- `sdks/python/` -- Full Python SDK
