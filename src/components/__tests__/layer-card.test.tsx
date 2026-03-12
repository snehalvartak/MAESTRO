import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { LayerCard } from '../layer-card'
import type { LayerData } from '@/lib/types'

const baseLayer: LayerData = {
  id: 'foundation-models',
  name: 'Foundation Models',
  description: 'Core AI models.',
  threat: null,
  riskScore: null,
  mitigation: null,
  status: 'pending',
}

const completeLayer: LayerData = {
  ...baseLayer,
  status: 'complete',
  threat: 'Model poisoning and data leakage risks identified.',
  riskScore: {
    severity: 'High',
    likelihood: 'Medium',
    riskLevel: 'High',
    rationale: 'Foundation models are critical attack surfaces in agentic systems.',
  },
  mitigation: {
    recommendation: 'Apply adversarial training and input validation.',
    reasoning: 'Reduces susceptibility to prompt injection and poisoning attacks.',
    caveats: 'Requires labeled adversarial data and ongoing monitoring.',
    complianceMapping: {
      nist: ['SI-3', 'SI-10', 'SC-8'],
      iso27001: ['A.8.8', 'A.8.2'],
      soc2: ['CC7.1', 'CC6.1'],
    },
  },
}

/** Opens the Mitigation Strategy accordion panel */
function openMitigationPanel() {
  fireEvent.click(screen.getByText('Mitigation Strategy'))
}

describe('LayerCard', () => {
  describe('status states', () => {
    it('renders layer name', () => {
      render(<LayerCard layer={baseLayer} />)
      expect(screen.getByText('Foundation Models')).toBeInTheDocument()
    })

    it('shows Pending badge when status is pending', () => {
      render(<LayerCard layer={baseLayer} />)
      expect(screen.getByText('Pending')).toBeInTheDocument()
    })

    it('shows Analyzing badge when status is analyzing', () => {
      render(<LayerCard layer={{ ...baseLayer, status: 'analyzing' }} />)
      expect(screen.getByText('Analyzing...')).toBeInTheDocument()
    })

    it('shows Complete badge when status is complete', () => {
      render(<LayerCard layer={completeLayer} />)
      expect(screen.getByText('Complete')).toBeInTheDocument()
    })

    it('shows Error badge and message when status is error', () => {
      render(<LayerCard layer={{ ...baseLayer, status: 'error' }} />)
      expect(screen.getByText('Error')).toBeInTheDocument()
      expect(screen.getByText('Analysis failed')).toBeInTheDocument()
    })
  })

  describe('risk score display', () => {
    it('shows risk level badge when riskScore is present', () => {
      render(<LayerCard layer={completeLayer} />)
      // Badge appears in both the card header and inside the accordion risk panel
      const riskBadges = screen.getAllByText(/Risk: High/)
      expect(riskBadges.length).toBeGreaterThanOrEqual(1)
    })

    it('does not show risk badge when riskScore is null', () => {
      render(<LayerCard layer={baseLayer} />)
      expect(screen.queryByText(/Risk:/)).not.toBeInTheDocument()
    })

    it('shows risk rationale inside threat accordion (open by default)', () => {
      render(<LayerCard layer={completeLayer} />)
      expect(screen.getByText('Foundation models are critical attack surfaces in agentic systems.')).toBeInTheDocument()
    })

    it('shows severity and likelihood labels', () => {
      render(<LayerCard layer={completeLayer} />)
      expect(screen.getByText(/Severity: High/)).toBeInTheDocument()
      expect(screen.getByText(/Likelihood: Medium/)).toBeInTheDocument()
    })
  })

  describe('compliance mapping display', () => {
    it('shows NIST controls in mitigation panel', () => {
      render(<LayerCard layer={completeLayer} />)
      openMitigationPanel()
      expect(screen.getByText('SI-3')).toBeInTheDocument()
      expect(screen.getByText('SI-10')).toBeInTheDocument()
      expect(screen.getByText('SC-8')).toBeInTheDocument()
    })

    it('shows ISO 27001 controls in mitigation panel', () => {
      render(<LayerCard layer={completeLayer} />)
      openMitigationPanel()
      expect(screen.getByText('A.8.8')).toBeInTheDocument()
      expect(screen.getByText('A.8.2')).toBeInTheDocument()
    })

    it('shows SOC 2 criteria in mitigation panel', () => {
      render(<LayerCard layer={completeLayer} />)
      openMitigationPanel()
      expect(screen.getByText('CC7.1')).toBeInTheDocument()
      expect(screen.getByText('CC6.1')).toBeInTheDocument()
    })

    it('shows framework labels in mitigation panel', () => {
      render(<LayerCard layer={completeLayer} />)
      openMitigationPanel()
      expect(screen.getByText('NIST SP 800-53:')).toBeInTheDocument()
      expect(screen.getByText('ISO 27001:2022:')).toBeInTheDocument()
      expect(screen.getByText('SOC 2:')).toBeInTheDocument()
    })

    it('does not show compliance section when complianceMapping is absent', () => {
      const layerNoCompliance: LayerData = {
        ...completeLayer,
        mitigation: {
          recommendation: 'Apply validation',
          reasoning: 'Security best practice',
          caveats: 'None',
        },
      }
      render(<LayerCard layer={layerNoCompliance} />)
      openMitigationPanel()
      expect(screen.queryByText('NIST SP 800-53:')).not.toBeInTheDocument()
    })

    it('does not show compliance section when arrays are empty', () => {
      const layerEmptyCompliance: LayerData = {
        ...completeLayer,
        mitigation: {
          recommendation: 'Apply validation',
          reasoning: 'Security best practice',
          caveats: 'None',
          complianceMapping: { nist: [], iso27001: [], soc2: [] },
        },
      }
      render(<LayerCard layer={layerEmptyCompliance} />)
      openMitigationPanel()
      expect(screen.queryByText('NIST SP 800-53:')).not.toBeInTheDocument()
    })
  })

  describe('mitigation content', () => {
    it('shows recommendation text in mitigation panel', () => {
      render(<LayerCard layer={completeLayer} />)
      openMitigationPanel()
      expect(screen.getByText('Apply adversarial training and input validation.')).toBeInTheDocument()
    })

    it('shows reasoning text in mitigation panel', () => {
      render(<LayerCard layer={completeLayer} />)
      openMitigationPanel()
      expect(screen.getByText('Reduces susceptibility to prompt injection and poisoning attacks.')).toBeInTheDocument()
    })

    it('shows caveats text in mitigation panel', () => {
      render(<LayerCard layer={completeLayer} />)
      openMitigationPanel()
      expect(screen.getByText('Requires labeled adversarial data and ongoing monitoring.')).toBeInTheDocument()
    })
  })
})
