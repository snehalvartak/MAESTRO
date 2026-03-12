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
  it('should accept valid OWASP Agentic AI and MITRE ATLAS mappings', () => {
    const mapping: ComplianceMapping = {
      owaspAgenticAI: ['ASI01', 'ASI06', 'ASI07'],
      mitreAtlas: ['AML.T0051', 'AML.T0080.001'],
    }
    expect(mapping.owaspAgenticAI).toHaveLength(3)
    expect(mapping.mitreAtlas).toHaveLength(2)
  })

  it('should accept empty arrays for each framework', () => {
    const mapping: ComplianceMapping = {
      owaspAgenticAI: [],
      mitreAtlas: [],
    }
    expect(mapping.owaspAgenticAI).toHaveLength(0)
    expect(mapping.mitreAtlas).toHaveLength(0)
  })

  it('should accept all valid OWASP Agentic AI ASI IDs', () => {
    const asiIds = ['ASI01', 'ASI02', 'ASI03', 'ASI04', 'ASI05', 'ASI06', 'ASI07', 'ASI08', 'ASI09', 'ASI10']
    const mapping: ComplianceMapping = { owaspAgenticAI: asiIds, mitreAtlas: [] }
    expect(mapping.owaspAgenticAI).toHaveLength(10)
    asiIds.forEach(id => expect(mapping.owaspAgenticAI).toContain(id))
  })

  it('should accept MITRE ATLAS technique and sub-technique IDs', () => {
    const atlasIds = ['AML.T0051', 'AML.T0051.001', 'AML.T0080', 'AML.T0080.001', 'AML.T0010']
    const mapping: ComplianceMapping = { owaspAgenticAI: [], mitreAtlas: atlasIds }
    expect(mapping.mitreAtlas).toContain('AML.T0051.001')
    expect(mapping.mitreAtlas).toContain('AML.T0080.001')
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
      recommendation: 'Sanitize inputs and validate tool outputs',
      reasoning: 'Prevents prompt injection and tool misuse',
      caveats: 'Requires ongoing prompt red-teaming',
      complianceMapping: {
        owaspAgenticAI: ['ASI01', 'ASI02'],
        mitreAtlas: ['AML.T0051', 'AML.T0051.001'],
      },
    }
    expect(mitigation.complianceMapping?.owaspAgenticAI).toContain('ASI01')
    expect(mitigation.complianceMapping?.mitreAtlas).toContain('AML.T0051.001')
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
          owaspAgenticAI: ['ASI04', 'ASI06'],
          mitreAtlas: ['AML.T0020', 'AML.T0018'],
        },
      },
      status: 'complete',
    }
    expect(layer.riskScore?.riskLevel).toBe('High')
    expect(layer.mitigation?.complianceMapping?.owaspAgenticAI).toContain('ASI04')
    expect(layer.mitigation?.complianceMapping?.mitreAtlas).toContain('AML.T0020')
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
