export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low';

export type RiskScore = {
  severity: RiskLevel;
  likelihood: 'High' | 'Medium' | 'Low';
  riskLevel: RiskLevel;
  rationale: string;
};

export type ComplianceMapping = {
  owaspAgenticAI: string[];  // ASI01–ASI10 (OWASP Top 10 for Agentic Applications 2026)
  mitreAtlas: string[];      // AML.Txxxx  (MITRE ATLAS v5.4 techniques)
};

export type Mitigation = {
  recommendation: string;
  reasoning: string;
  caveats: string;
  complianceMapping?: ComplianceMapping;
};

export type LayerStatus = "pending" | "analyzing" | "complete" | "error";

export type LayerData = {
  id: string;
  name: string;
  description: string;
  threat: string | null;
  riskScore: RiskScore | null;
  mitigation: Mitigation | null;
  status: LayerStatus;
};

export type UseCase = {
  value: string;
  label: string;
  description: string;
};
