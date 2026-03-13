'use server';
/**
 * @fileOverview Generates an executive summary of a MAESTRO threat analysis.
 *
 * - generateExecutiveSummary - A function that creates a high-level summary.
 * - GenerateExecutiveSummaryInput - The input type for the function.
 * - GenerateExecutiveSummaryOutput - The return type for the function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

const RiskScoreSchema = z.object({
  severity: z.enum(['Critical', 'High', 'Medium', 'Low']),
  likelihood: z.enum(['High', 'Medium', 'Low']),
  riskLevel: z.enum(['Critical', 'High', 'Medium', 'Low']),
  rationale: z.string(),
});

const LayerDataSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  threat: z.string().nullable(),
  riskScore: RiskScoreSchema.nullable().optional(),
  mitigation: z.object({
    recommendation: z.string(),
    reasoning: z.string(),
    caveats: z.string(),
    complianceMapping: z.object({
      owaspAgenticAI: z.array(z.string()),
      mitreAtlas: z.array(z.string()),
    }).optional(),
  }).nullable(),
  status: z.enum(['pending', 'analyzing', 'complete', 'error']),
});

const GenerateExecutiveSummaryInputSchema = z.object({
  architectureDescription: z.string().describe('The system architecture that was analyzed.'),
  analysisResults: z.array(LayerDataSchema).describe('An array of threat analysis results for each MAESTRO layer.'),
});
export type GenerateExecutiveSummaryInput = z.infer<typeof GenerateExecutiveSummaryInputSchema>;

const GenerateExecutiveSummaryOutputSchema = z.object({
  summary: z.string().describe('A Markdown-formatted executive summary of the threat analysis.'),
});
export type GenerateExecutiveSummaryOutput = z.infer<typeof GenerateExecutiveSummaryOutputSchema>;

export async function generateExecutiveSummary(input: GenerateExecutiveSummaryInput): Promise<GenerateExecutiveSummaryOutput> {
  return generateExecutiveSummaryFlow(input);
}

const prompt = ai.definePrompt({
  name: 'generateExecutiveSummaryPrompt',
  input: {schema: GenerateExecutiveSummaryInputSchema},
  output: {schema: GenerateExecutiveSummaryOutputSchema},
  prompt: `You are a principal security analyst. Your task is to write a high-level executive summary for a MAESTRO threat analysis report.

The summary should:
1.  Briefly acknowledge the analyzed architecture.
2.  Include a **Risk Overview** table showing the risk level (Critical/High/Medium/Low) for each MAESTRO layer.
3.  Highlight the most critical threats identified across all layers, referencing their risk levels.
4.  Mention the key mitigation themes or the most important recommended actions.
5.  Note the most frequently mapped OWASP Agentic AI (ASI) and MITRE ATLAS (AML.T) IDs across layers, highlighting which agentic threat categories are most prevalent.
6.  Conclude with a statement about the importance of a defense-in-depth strategy.
7.  Be concise, professional, and suitable for a leadership audience.
8.  Format the output as a single Markdown string.
9.  Include a link to the MAESTRO framework: https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro

**Analyzed Architecture:**
{{{architectureDescription}}}

**Analysis Results:**
{{#each analysisResults}}
---
**Layer: {{name}}**
**Status: {{status}}**
{{#if riskScore}}
**Risk Level: {{riskScore.riskLevel}}** (Severity: {{riskScore.severity}}, Likelihood: {{riskScore.likelihood}})
**Risk Rationale:** {{riskScore.rationale}}
{{/if}}
{{#if threat}}
**Threats:**
{{{threat}}}
{{/if}}
{{#if mitigation}}
**Mitigation:**
- **Recommendation:** {{mitigation.recommendation}}
- **Reasoning:** {{mitigation.reasoning}}
{{#if mitigation.complianceMapping}}
- **OWASP Agentic AI:** {{mitigation.complianceMapping.owaspAgenticAI}}
- **MITRE ATLAS:** {{mitigation.complianceMapping.mitreAtlas}}
{{/if}}
{{/if}}
{{/each}}

Based on the provided details, generate the executive summary.`,
});


const generateExecutiveSummaryFlow = ai.defineFlow(
  {
    name: 'generateExecutiveSummaryFlow',
    inputSchema: GenerateExecutiveSummaryInputSchema,
    outputSchema: GenerateExecutiveSummaryOutputSchema,
  },
  async input => {
    const {output} = await prompt(input);
    if (!output) {
      throw new Error('AI model returned null output for executive summary. Schema validation failed: provided data is null.');
    }
    return output;
  }
);
