// llm.ts - the agent's model client, chosen by LLM_MODE:
//   scripted (default)  deterministic fake with the OpenAI `chat.completions.create(...).withResponse()` shape
//   nearai              NEAR AI Cloud (z-ai/glm-5.3-flash); each turn's TEE receipt is verified, chat id recorded
//   openrouter          no receipts: every turn is unverified, so the guard holds payments for a human
import type OpenAI from 'openai';
import { makeClient } from '../llm/llm.ts';
import { fetchAndVerify } from '../llm/near-attest.ts';
import { attestationCache, createCapturingFetch, receiptVerifier } from '../llm/verified-fetch.ts';
import type { LlmMode } from '../lib/env.ts';
import type { TurnTrust } from './guard.ts';

export const NEARAI_MODEL = 'z-ai/glm-5.3-flash';
export const OPENROUTER_MODEL = 'openai/gpt-5-nano';

export type ChatParams = OpenAI.ChatCompletionCreateParamsNonStreaming;

/** The subset of the OpenAI client the runtime uses. */
export interface ChatClient {
  chat: { completions: { create(params: ChatParams): { withResponse(): Promise<{ data: OpenAI.ChatCompletion; response: Response }> } } };
}

export interface AgentLlm {
  mode: LlmMode;
  model: string;
  client: ChatClient;
  /** Called after each completion, before its tools run. Never throws: failures come back unverified. */
  trust(completion: OpenAI.ChatCompletion, response: Response): Promise<TurnTrust>;
  /** startup attestation summary (nearai with attest) */
  attestation?: unknown;
}

// ---------------------------------------------------------------- scripted
export interface ScriptedToolCall {
  name: string;
  /** an object is JSON-encoded; a string is passed through as-is (to test malformed model output) */
  arguments: Record<string, unknown> | string;
}
export interface ScriptedTurn {
  content?: string;
  tool_calls?: ScriptedToolCall[];
}

/** Returns the scripted turns in order, then a final "Done." turn. Ignores the conversation. */
export function scriptedClient(turns: readonly ScriptedTurn[], model = 'scripted'): ChatClient {
  let i = 0;
  let call = 0;
  return {
    chat: {
      completions: {
        create(_params: ChatParams) {
          const turn = turns[i++] ?? { content: 'Done.' };
          const tool_calls = (turn.tool_calls ?? []).map((t) => ({
            id: `call_${++call}`,
            type: 'function' as const,
            function: { name: t.name, arguments: typeof t.arguments === 'string' ? t.arguments : JSON.stringify(t.arguments) },
          }));
          const data: OpenAI.ChatCompletion = {
            id: `scripted-${i}`,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model,
            choices: [{
              index: 0,
              finish_reason: tool_calls.length ? 'tool_calls' : 'stop',
              logprobs: null,
              message: { role: 'assistant', content: turn.content ?? null, refusal: null, ...(tool_calls.length ? { tool_calls } : {}) },
            }],
          };
          const response = new Response(null, { headers: { 'x-serving-provider': 'scripted' } });
          return { withResponse: async () => ({ data, response }) };
        },
      },
    },
  };
}

// ---------------------------------------------------------------- real clients
function wrap(openai: OpenAI): ChatClient {
  return {
    chat: {
      completions: {
        create: (params: ChatParams) => {
          const p = openai.chat.completions.create({ ...params, stream: false });
          return { withResponse: async () => {
            const { data, response } = await p.withResponse();
            return { data, response };
          } };
        },
      },
    },
  };
}

export interface MakeLlmOptions {
  turns?: readonly ScriptedTurn[];
  model?: string;
  /** nearai: verify the model attestation once at startup (network, free) */
  attest?: boolean;
  /** nearai: verify each turn's receipt (default true) */
  receipts?: boolean;
}

export async function makeAgentLlm(mode: LlmMode, o: MakeLlmOptions = {}): Promise<AgentLlm> {
  if (mode === 'scripted') {
    return { mode, model: 'scripted', client: scriptedClient(o.turns ?? []), trust: async (c) => ({ verified: true, kind: 'scripted', chatId: c.id }) };
  }
  if (mode === 'openrouter') {
    const model = o.model ?? OPENROUTER_MODEL;
    return {
      mode,
      model,
      client: wrap(makeClient('openrouter')),
      trust: async (c) => ({ verified: false, kind: 'unverified', chatId: c.id, detail: 'openrouter turns carry no TEE receipt' }),
    };
  }
  const model = o.model ?? NEARAI_MODEL;
  const capturing = createCapturingFetch();
  const client = wrap(makeClient('near', { fetch: capturing.fetch }));
  const attestation = o.attest ? await fetchAndVerify(model) : undefined;
  const verify = receiptVerifier(capturing.captured, attestationCache());
  const receipts = o.receipts ?? true;
  return {
    mode,
    model,
    client,
    attestation,
    async trust(c, response) {
      const servedBy = response.headers.get('x-serving-provider');
      if (!receipts) return { verified: false, kind: 'unverified', chatId: c.id, detail: `receipts off; served by ${servedBy ?? 'unknown'}` };
      try {
        const v = await verify(c);
        return { verified: true, kind: v.verdict, chatId: c.id, detail: `signer ${v.signer}` };
      } catch (e) {
        return { verified: false, kind: 'unverified', chatId: c.id, detail: (e as Error).message };
      }
    },
  };
}
