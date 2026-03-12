import { describe, it, expect } from 'vitest'
import type { RiskScore, ComplianceMapping, Mitigation, LayerData } from '../types'

describe('RiskScore type', () => {
  it('should accept valid risk scores', () => {
    const riskScore: RiskScore = {
      severity: 'Critical',
      likelihood: 'High',
      riskLevel: 'Critical',
      rationale: 'Direct exposure to untrusted inputs with no validation.',
    }
    expect(riskScore.severity).toBe('Critical')
    expect(riskScore.likelihood).toBe('High')
    expect(riskScore.riskLevel).toBe('Critical')
    expect(riskScore.rationale).toBeTruthy()
  })

  it('should accept all valid severity levels', () => {
    const levels = ['Critical', 'High', 'Medium', 'Low'] as const
    levels.forEach((level) => {
      const score: RiskScore = {
        severity: level,
        likelihood: 'Medium',
        riskLevel: level,
        rationale: 'test',
      }
      expect(score.severity).toBe(level)
      expect(score.riskLevel).toBe(level)
    })
  })

  it('should accept all valid likelihood levels', () => {
    const likelihoods = ['High', 'Medium', 'Low'] as const
    likelihoods.forEach((likelihood) => {
      const score: RiskScore = {
        severity: 'High',
        likelihood,
        riskLevel: 'High',
        rationale: 'test',
      }
      expect(score.likelihood).toBe(likelihood)
    })
  })
})

describe('ComplianceMapping type', () => {
  it('should accept valid compliance mappings', () => {
    const mapping: ComplianceMapping = {
      nist: ['AC-2', 'SI-3', 'SC-8'],
      iso27001: ['A.8.2', 'A.5.15'],
      soc2: ['CC6.1', 'CC7.2'],
    }
    expect(mapping.nist).toHaveLength(3)
    expect(mapping.iso27001).toHaveLength(2)
    expect(mapping.soc2).toHaveLength(2)
  })

  it('should accept empty arrays for each framework', () => {
    const mapping: ComplianceMapping = {
      nist: [],
      iso27001: [],
      soc2: [],
    }
    expect(mapping.nist).toHaveLength(0)
    expect(mapping.iso27001).toHaveLength(0)
    expect(mapping.soc2).toHaveLength(0)
  })
})

describe('Mitigation type', () => {
  it('should work without complianceMapping (optional)', () => {
    const mitigation: Mitigation = {
      recommendation: 'Implement input validation',
      reasoning: 'Prevents injection attacks',
      caveats: 'May impact performance',
    }
    expect(mitigation.complianceMapping).toBeUndefined()
  })

  it('should accept complianceMapping when provided', () => {
    const mitigation: Mitigation = {
      recommendation: 'Use encryption at rest',
      reasoning: 'Protects stored data',
      caveats: 'Key management overhead',
      complianceMapping: {
        nist: ['SC-28'],
        iso27001: ['A.8.24'],
        soc2: ['CC6.7'],
      },
    }
    expect(mitigation.complianceMapping?.nist).toContain('SC-28')
    expect(mitigation.complianceMapping?.iso27001).toContain('A.8.24')
    expect(mitigation.complianceMapping?.soc2).toContain('CC6.7')
  })
})

describe('LayerData type', () => {
  it('should initialize with null riskScore', () => {
    const layer: LayerData = {
      id: 'foundation-models',
      name: 'Foundation Models',
      description: 'Core AI models.',
      threat: null,
      riskScore: null,
      mitigation: null,
      status: 'pending',
    }
    expect(layer.riskScore).toBeNull()
    expect(layer.status).toBe('pending')
  })

  it('should accept complete layer data with risk and compliance', () => {
    const layer: LayerData = {
      id: 'foundation-models',
      name: 'Foundation Models',
      description: 'Core AI models.',
      threat: '## Threats\n- Model poisoning',
      riskScore: {
        severity: 'High',
        likelihood: 'Medium',
        riskLevel: 'High',
        rationale: 'Foundation models are key attack surfaces.',
      },
      mitigation: {
        recommendation: 'Apply adversarial training',
        reasoning: 'Reduces susceptibility to poisoning',
        caveats: 'Requires labeled adversarial data',
        complianceMapping: {
          nist: ['SI-3', 'SI-10'],
          iso27001: ['A.8.8'],
          soc2: ['CC7.1'],
        },
      },
      status: 'complete',
    }
    expect(layer.riskScore?.riskLevel).toBe('High')
    expect(layer.mitigation?.complianceMapping?.nist).toContain('SI-3')
    expect(layer.status).toBe('complete')
  })

  it('should accept all valid status values', () => {
    const statuses = ['pending', 'analyzing', 'complete', 'error'] as const
    statuses.forEach((status) => {
      const layer: LayerData = {
        id: 'test',
        name: 'Test',
        description: 'Test layer',
        threat: null,
        riskScore: null,
        mitigation: null,
        status,
      }
      expect(layer.status).toBe(status)
    })
  })
})
