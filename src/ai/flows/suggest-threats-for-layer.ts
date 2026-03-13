'use server';
/**
 * @fileOverview Generates a comprehensive threat analysis for a specific MAESTRO layer
 * based on a provided system architecture description, including risk scoring.
 *
 * - suggestThreatsForLayer - A function that initiates the threat analysis process.
 * - SuggestThreatsForLayerInput - The input type for the suggestThreatsForLayer function.
 * - SuggestThreatsForLayerOutput - The return type for the suggestThreatsForLayer function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

const SuggestThreatsForLayerInputSchema = z.object({
  architectureDescription: z
    .string()
    .describe('A detailed description of the system architecture.'),
  layerName: z.string().describe('The name of the MAESTRO layer to analyze.'),
  layerDescription: z.string().describe('The description of the MAESTRO layer.'),
});
export type SuggestThreatsForLayerInput = z.infer<
  typeof SuggestThreatsForLayerInputSchema
>;

const RiskScoreSchema = z.object({
  severity: z
    .enum(['Critical', 'High', 'Medium', 'Low'])
    .describe('The severity of the identified threats for this layer.'),
  likelihood: z
    .enum(['High', 'Medium', 'Low'])
    .describe('The likelihood of these threats being exploited.'),
  riskLevel: z
    .enum(['Critical', 'High', 'Medium', 'Low'])
    .describe('The overall risk level combining severity and likelihood.'),
  rationale: z
    .string()
    .describe('A brief rationale explaining the risk score assigned.'),
});

const SuggestThreatsForLayerOutputSchema = z.object({
  threatAnalysis: z
    .string()
    .describe(
      'A comprehensive threat analysis for the specified layer, formatted in Markdown.'
    ),
  riskScore: RiskScoreSchema.describe(
    'A structured risk score for the identified threats in this layer.'
  ),
});
export type SuggestThreatsForLayerOutput = z.infer<
  typeof SuggestThreatsForLayerOutputSchema
>;

export async function suggestThreatsForLayer(
  input: SuggestThreatsForLayerInput
): Promise<SuggestThreatsForLayerOutput> {
  return suggestThreatsForLayerFlow(input);
}

const prompt = ai.definePrompt({
  name: 'suggestThreatsForLayerPrompt',
  input: {schema: SuggestThreatsForLayerInputSchema},
  output: {schema: SuggestThreatsForLayerOutputSchema},
  prompt: `You are a security analyst specializing in identifying potential security vulnerabilities in multi-agent systems, with a focus on the MAESTRO architecture.

Your task is to generate a threat analysis for the specified MAESTRO layer, along with a structured risk score.

**System Architecture Description:**
{{{architectureDescription}}}

**MAESTRO Layer to Analyze:** {{layerName}}
**Layer Description:** {{{layerDescription}}}

**Agentic Factors to Consider:**
- Non-Determinism
- Autonomy
- No Trust Boundary
- Dynamic Identity and Access Control
- Agent to Agent interactions, delegations, and communication complexity

**Instructions:**
1.  Analyze the provided system architecture and the MAESTRO layer description.
2.  Generate a threat analysis structured into two categories, formatted as Markdown.
3.  **Category 1: Traditional Threats:** Identify inherent security threats for this layer, ignoring agentic factors. For example, for 'Foundation Models', this could include model poisoning, data leakage, or member inference attacks.
4.  **Category 2: Agentic Threats:** Reason about how each of the "Agentic Factors to Consider" could introduce new threats or exacerbate existing ones within this specific layer. If a factor applies, describe the potential threat. If it does not apply, you can state that.
5.  Format the threat analysis as a single Markdown string. Use headings, bold text, and lists to make the report clear and readable.
6.  Assign a structured risk score:
    - **severity**: Overall severity of identified threats (Critical/High/Medium/Low)
    - **likelihood**: Likelihood of exploitation given the architecture (High/Medium/Low)
    - **riskLevel**: Combined overall risk level (Critical/High/Medium/Low)
    - **rationale**: 1-2 sentence explanation of the risk score

**Threat Analysis:**`,
});

const suggestThreatsForLayerFlow = ai.defineFlow(
  {
    name: 'suggestThreatsForLayerFlow',
    inputSchema: SuggestThreatsForLayerInputSchema,
    outputSchema: SuggestThreatsForLayerOutputSchema,
  },
  async input => {
    const {output} = await prompt(input);
    if (!output) {
      throw new Error('AI model returned null output for threat analysis. Schema validation failed: provided data is null.');
    }
    return output;
  }
);
