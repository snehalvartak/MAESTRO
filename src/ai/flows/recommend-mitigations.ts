// recommend-mitigations.ts
'use server';
/**
 * @fileOverview AI-driven mitigation strategies for identified threats,
 * including compliance framework mappings (NIST, ISO 27001, SOC 2).
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
  nist: z
    .array(z.string())
    .describe('Relevant NIST SP 800-53 control identifiers (e.g., AC-2, SI-3).'),
  iso27001: z
    .array(z.string())
    .describe('Relevant ISO 27001:2022 control identifiers (e.g., A.8.2, A.5.15).'),
  soc2: z
    .array(z.string())
    .describe('Relevant SOC 2 Trust Service Criteria (e.g., CC6.1, CC7.2).'),
});

const RecommendMitigationsOutputSchema = z.object({
  recommendation: z.string().describe('Recommended mitigation strategy.'),
  reasoning: z.string().describe('Reasoning behind the recommendation.'),
  caveats: z.string().describe('Caveats or limitations of the mitigation strategy.'),
  complianceMapping: ComplianceMappingSchema.describe(
    'Compliance framework controls relevant to this mitigation.'
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
  prompt: `You are a cybersecurity expert providing mitigation strategies for identified threats in a MAESTRO architecture.

For the threat described below, provide:
1. A **recommendation** for mitigation - a concise, actionable strategy.
2. The **reasoning** behind that recommendation - why this approach addresses the threat.
3. Any **caveats** or limitations of the strategy.
4. A **compliance mapping** linking the mitigation to relevant controls in:
   - NIST SP 800-53 (use control IDs like AC-2, SI-3, IA-5, SC-8, etc.)
   - ISO 27001:2022 (use control IDs like A.8.2, A.5.15, A.8.24, etc.)
   - SOC 2 Trust Service Criteria (use criteria IDs like CC6.1, CC6.6, CC7.2, etc.)

Provide 2-5 relevant controls per framework. Only include controls that are genuinely applicable.

Threat Description: {{{threatDescription}}}
MAESTRO Layer: {{{layer}}}

Ensure the response is clear, concise, and technically accurate.
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
