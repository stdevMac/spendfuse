// llm.ts - one OpenAI-SDK client for NEAR AI Cloud (primary) or OpenRouter (fallback),
// plus an append-only tool-calling loop. Node >= 22 (openai@7 floor); run with Node >= 24
// for native type stripping. deps: openai@7.53.0
import OpenAI from 'openai';

export type Provider = 'near' | 'openrouter';

export const PROVIDERS = {
  near: { baseURL: process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1', keyEnv: 'NEARAI_API_KEY' },
  openrouter: { baseURL: 'https://openrouter.ai/api/v1', keyEnv: 'OPENROUTER_API_KEY' },
} as const;

export function makeClient(
  provider: Provider,
  opts: { apiKey?: string; fetch?: typeof fetch; appUrl?: string; appTitle?: string; maxRetries?: number } = {},
): OpenAI {
  const { baseURL, keyEnv } = PROVIDERS[provider];
  const apiKey = opts.apiKey ?? process.env[keyEnv];
  if (!apiKey) throw new Error(`missing ${keyEnv}`);
  return new OpenAI({
    baseURL,
    apiKey,
    timeout: 60_000,
    maxRetries: opts.maxRetries ?? 2,
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
    defaultHeaders:
      provider === 'near'
        ? // 400 instead of silently remapping a retired/alias model id to another model
          { 'x-no-aliasing': 'true' }
        : // optional OpenRouter app attribution headers
          { 'HTTP-Referer': opts.appUrl ?? 'https://github.com/your-org/spendfuse', 'X-OpenRouter-Title': opts.appTitle ?? 'Spendfuse' },
  });
}

export type ToolImpl = (args: Record<string, unknown>, call: OpenAI.ChatCompletionMessageFunctionToolCall) => unknown | Promise<unknown>;

export interface StepLog {
  id: string;
  model: string;
  finishReason: string | null;
  usage?: OpenAI.CompletionUsage & { cost?: number }; // OpenRouter adds usage.cost (credits = USD)
  toolCalls: { id: string; name: string; arguments: string }[];
  servedBy?: string | null; // NEAR: x-serving-provider response header (near | chutes | tinfoil | non-attested)
  verified?: unknown; // whatever RunAgentParams.verify returned for this turn (e.g. a TEE receipt verdict)
}

/** Thrown when `verify` rejects a model turn. Nothing from that turn ran; `steps` holds the turns that did. */
export class AgentHalted extends Error {
  readonly steps: StepLog[];
  readonly completion: OpenAI.ChatCompletion;
  constructor(message: string, steps: StepLog[], completion: OpenAI.ChatCompletion, cause: unknown) {
    super(message, { cause });
    this.name = 'AgentHalted';
    this.steps = steps;
    this.completion = completion;
  }
}

export interface RunAgentParams {
  client: OpenAI;
  model: string;
  messages: OpenAI.ChatCompletionMessageParam[];
  tools: OpenAI.ChatCompletionTool[];
  impls: Record<string, ToolImpl>;
  /** provider-specific extras, e.g. { thinking_token_budget: 512 } (NEAR GLM) or { reasoning: { effort: 'low' } } (OpenRouter) */
  extra?: Record<string, unknown>;
  maxSteps?: number;
  /** Runs after each completion and BEFORE any of its tool calls execute (e.g. a TEE receipt check). Throw to halt. */
  verify?: (completion: OpenAI.ChatCompletion, response: Response) => unknown | Promise<unknown>;
}

/**
 * Append-only loop: every assistant turn is echoed back exactly as received (content, tool_calls and the
 * provider's reasoning field), every tool_call id gets exactly one tool message, nothing is rewritten.
 * Tool arguments are model output: treat them as untrusted input (Spendfuse's contract is the real guard).
 */
export async function runAgent({ client, model, messages, tools, impls, extra = {}, maxSteps = 8, verify }: RunAgentParams) {
  const history: OpenAI.ChatCompletionMessageParam[] = [...messages];
  const steps: StepLog[] = [];
  for (let step = 0; step < maxSteps; step++) {
    const params = { model, messages: history, tools, tool_choice: 'auto', ...extra } as OpenAI.ChatCompletionCreateParamsNonStreaming;
    const { data: completion, response } = await client.chat.completions.create(params).withResponse();
    const choice = completion.choices[0];
    if (!choice) throw new Error(`no choices in completion ${completion.id}`);
    const msg = choice.message;
    const toolCalls = msg.tool_calls ?? [];

    // Fail closed: a turn that does not verify never reaches the tools (or the history).
    let verified: unknown;
    if (verify) {
      try {
        verified = await verify(completion, response);
      } catch (e) {
        throw new AgentHalted(`model turn ${completion.id} failed verification: ${(e as Error).message}`, steps, completion, e);
      }
    }

    // Echo the assistant turn. NEAR returns reasoning in `reasoning_content` (also accepts `reasoning`);
    // OpenRouter returns `reasoning` + `reasoning_details` and wants `reasoning_details` back unchanged.
    const raw = msg as unknown as Record<string, unknown>;
    const echo: Record<string, unknown> = { role: 'assistant', content: msg.content ?? null };
    if (toolCalls.length) echo.tool_calls = toolCalls;
    if (raw.reasoning_details) echo.reasoning_details = raw.reasoning_details;
    else if (raw.reasoning_content) echo.reasoning_content = raw.reasoning_content;
    else if (raw.reasoning) echo.reasoning = raw.reasoning;
    history.push(echo as unknown as OpenAI.ChatCompletionAssistantMessageParam);

    steps.push({
      id: completion.id,
      model: completion.model,
      finishReason: choice.finish_reason,
      usage: completion.usage as StepLog['usage'],
      servedBy: response.headers.get('x-serving-provider'),
      toolCalls: toolCalls.flatMap((c) => (c.type === 'function' ? [{ id: c.id, name: c.function.name, arguments: c.function.arguments }] : [])),
      verified,
    });

    if (toolCalls.length === 0) return { final: msg.content ?? '', steps, messages: history };

    for (const call of toolCalls) {
      let result: unknown;
      if (call.type !== 'function') {
        result = { error: `unsupported tool call type ${call.type}` }; // still answer the id, or the next request 400s
      } else {
        try {
          const impl = impls[call.function.name];
          if (!impl) throw new Error(`unknown tool ${call.function.name}`);
          const args = JSON.parse(call.function.arguments || '{}');
          if (typeof args !== 'object' || args === null || Array.isArray(args)) throw new Error('tool arguments must be a JSON object');
          result = await impl(args, call);
        } catch (e) {
          result = { error: (e as Error).message };
        }
      }
      history.push({ role: 'tool', tool_call_id: call.id, content: typeof result === 'string' ? result : JSON.stringify(result) });
    }
  }
  throw new Error(`no final answer after ${maxSteps} steps`);
}

// ---- Spendfuse-style tool schema (OpenAI function-tool format; identical on NEAR and OpenRouter) ----
export const SPENDFUSE_TOOLS: OpenAI.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
      name: 'pay',
      description: 'Request a NEAR transfer from the policy vault. The vault enforces limits; large amounts queue for approval.',
      parameters: {
        type: 'object',
        properties: {
          receiver_id: { type: 'string', description: 'NEAR account id, e.g. alice.testnet' },
          amount_near: { type: 'string', description: 'Decimal NEAR amount as a string, e.g. "1.5"' },
          memo: { type: 'string', description: 'Why this payment is needed' },
        },
        required: ['receiver_id', 'amount_near', 'memo'],
        additionalProperties: false,
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_policy',
      description: 'Read the current vault policy: per-tx limit, daily limit, remaining allowance.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
    },
  },
];

if (import.meta.main) {
  // Live demo (costs a fraction of a cent): node llm.ts near z-ai/glm-5.3-flash
  const provider = (process.argv[2] ?? 'near') as Provider;
  const model = process.argv[3] ?? (provider === 'near' ? 'z-ai/glm-5.3-flash' : 'openai/gpt-5-nano');
  const client = makeClient(provider);
  const out = await runAgent({
    client,
    model,
    tools: SPENDFUSE_TOOLS,
    impls: {
      get_policy: () => ({ per_tx_limit_near: '2', daily_remaining_near: '5' }),
      pay: (a) => ({ status: 'simulated', ...a }), // never sign anything from a demo
    },
    messages: [
      { role: 'system', content: 'You are a treasury agent. Only pay invoices the user asked for.' },
      { role: 'user', content: 'Pay bob.testnet 1 NEAR for the logo invoice #42.' },
    ],
    extra: provider === 'near' && model.startsWith('z-ai/glm') ? { thinking_token_budget: 512 } : {},
  });
  console.log(JSON.stringify({ final: out.final, steps: out.steps }, null, 2));
}
