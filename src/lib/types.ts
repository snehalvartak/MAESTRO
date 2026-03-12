export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low';

export type RiskScore = {
  severity: RiskLevel;
  likelihood: 'High' | 'Medium' | 'Low';
  riskLevel: RiskLevel;
  rationale: string;
};

export type ComplianceMapping = {
  nist: string[];
  iso27001: string[];
  soc2: string[];
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
