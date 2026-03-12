// recommend-mitigations.ts
'use server';
/**
 * @fileOverview AI-driven mitigation strategies for identified threats,
 * including mappings to OWASP Top 10 for Agentic Applications (2026) and MITRE ATLAS v5.4.
 *
 * - recommendMitigations - A function that generates mitigation strategies.
 * - RecommendMitigationsInput - The input type for the recommendMitigations function.
 * - RecommendMitigationsOutput - The return type for the recommendMitigations function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

const RecommendMitigationsInputSchema = z.object({
  threatDescription: z.string().describe('Description of the identified threat.'),
  layer: z.string().describe('The MAESTRO layer the threat belongs to.'),
});
export type RecommendMitigationsInput = z.infer<typeof RecommendMitigationsInputSchema>;

const ComplianceMappingSchema = z.object({
  owaspAgenticAI: z
    .array(z.string())
    .describe(
      'Relevant OWASP Top 10 for Agentic Applications 2026 IDs. ' +
      'Valid values: ASI01 (Agent Goal Hijack), ASI02 (Tool Misuse & Exploitation), ' +
      'ASI03 (Identity & Privilege Abuse), ASI04 (Agentic Supply Chain Vulnerabilities), ' +
      'ASI05 (Unexpected Code Execution), ASI06 (Memory & Context Poisoning), ' +
      'ASI07 (Insecure Inter-Agent Communication), ASI08 (Cascading Failures), ' +
      'ASI09 (Human-Agent Trust Exploitation), ASI10 (Rogue Agents).'
    ),
  mitreAtlas: z
    .array(z.string())
    .describe(
      'Relevant MITRE ATLAS v5.4 technique IDs (e.g., AML.T0051, AML.T0080.001). ' +
      'Use the most specific applicable technique. Examples: ' +
      'AML.T0051 (LLM Prompt Injection), AML.T0051.001 (Indirect Prompt Injection), ' +
      'AML.T0054 (LLM Jailbreak), AML.T0020 (Poison Training Data), ' +
      'AML.T0018 (Manipulate AI Model), AML.T0010 (AI Supply Chain Compromise), ' +
      'AML.T0080 (AI Agent Context Poisoning), AML.T0080.001 (Memory Poisoning), ' +
      'AML.T0082 (RAG Credential Harvesting), AML.T0083 (Credentials from AI Agent Config), ' +
      'AML.T0084 (Discover AI Agent Configuration), AML.T0086 (Exfiltration via AI Agent Tool), ' +
      'AML.T0098 (AI Agent Tool Credential Harvesting), AML.T0099 (AI Agent Tool Data Poisoning), ' +
      'AML.T0101 (Data Destruction via AI Agent Tool), AML.T0053 (AI Agent Tool Invocation), ' +
      'AML.T0057 (LLM Data Leakage), AML.T0070 (RAG Poisoning), AML.T0024 (Exfiltration via AI Inference API).'
    ),
});

const RecommendMitigationsOutputSchema = z.object({
  recommendation: z.string().describe('Recommended mitigation strategy.'),
  reasoning: z.string().describe('Reasoning behind the recommendation.'),
  caveats: z.string().describe('Caveats or limitations of the mitigation strategy.'),
  complianceMapping: ComplianceMappingSchema.describe(
    'Mapping to OWASP Agentic AI Top 10 and MITRE ATLAS techniques relevant to this mitigation.'
  ),
});
export type RecommendMitigationsOutput = z.infer<typeof RecommendMitigationsOutputSchema>;

export async function recommendMitigations(input: RecommendMitigationsInput): Promise<RecommendMitigationsOutput> {
  return recommendMitigationsFlow(input);
}

const prompt = ai.definePrompt({
  name: 'recommendMitigationsPrompt',
  input: {schema: RecommendMitigationsInputSchema},
  output: {schema: RecommendMitigationsOutputSchema},
  prompt: `You are a cybersecurity expert specializing in agentic AI systems, providing mitigation strategies for threats identified using the MAESTRO framework.

For the threat described below, provide:
1. A **recommendation** — a concise, actionable mitigation strategy.
2. The **reasoning** — why this approach addresses the specific agentic AI threat.
3. Any **caveats** or limitations of the strategy.
4. A **compliance mapping** to agentic-AI-specific security frameworks:

   **OWASP Top 10 for Agentic Applications 2026** (use ASI IDs):
   - ASI01: Agent Goal Hijack
   - ASI02: Tool Misuse & Exploitation
   - ASI03: Identity & Privilege Abuse
   - ASI04: Agentic Supply Chain Vulnerabilities
   - ASI05: Unexpected Code Execution
   - ASI06: Memory & Context Poisoning
   - ASI07: Insecure Inter-Agent Communication
   - ASI08: Cascading Failures
   - ASI09: Human-Agent Trust Exploitation
   - ASI10: Rogue Agents

   **MITRE ATLAS v5.4** (use AML.T technique IDs, include sub-techniques where applicable):
   Key agentic techniques include: AML.T0051/AML.T0051.001 (LLM Prompt Injection/Indirect),
   AML.T0054 (LLM Jailbreak), AML.T0080/AML.T0080.001 (AI Agent Context Poisoning/Memory),
   AML.T0020 (Poison Training Data), AML.T0010 (AI Supply Chain Compromise),
   AML.T0053 (AI Agent Tool Invocation), AML.T0082 (RAG Credential Harvesting),
   AML.T0086 (Exfiltration via AI Agent Tool), AML.T0057 (LLM Data Leakage),
   AML.T0070 (RAG Poisoning), AML.T0099 (AI Agent Tool Data Poisoning),
   AML.T0101 (Data Destruction via AI Agent Tool), AML.T0098 (AI Agent Tool Credential Harvesting).

Only include IDs that are genuinely applicable to this specific threat. Provide 1-4 IDs per framework.

Threat Description: {{{threatDescription}}}
MAESTRO Layer: {{{layer}}}
`,
});

const recommendMitigationsFlow = ai.defineFlow(
  {
    name: 'recommendMitigationsFlow',
    inputSchema: RecommendMitigationsInputSchema,
    outputSchema: RecommendMitigationsOutputSchema,
  },
  async input => {
    const {output} = await prompt(input);
    return output!;
  }
);
