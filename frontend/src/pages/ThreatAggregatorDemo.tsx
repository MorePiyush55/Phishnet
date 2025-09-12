import React, { useState } from 'react';
import ThreatExplanationPanel from '../components/ThreatExplanationPanel';
import ThreatConfigurationPanel from '../components/ThreatConfigurationPanel';

// Sample threat result data
const SAMPLE_THREAT_RESULT = {
  target: "https://suspicious-phishing-site.com/login",
  target_type: "url",
  score: 0.85,
  level: "malicious" as const,
  confidence: 0.92,
  components: {
    ml_score: {
      score: 0.88,
      confidence: 0.94,
      weight: 0.25,
      explanation: "ML model detected multiple phishing indicators including suspicious domain patterns and content similarity to known phishing sites.",
      evidence_urls: ["http://localhost:8000/evidence/ml_features_123"],
      timestamp: Date.now() / 1000
    },
    llm_verdict: {
      score: 0.91,
      confidence: 0.89,
      weight: 0.20,
      explanation: "LLM analysis identified deceptive language patterns and credential harvesting forms typical of phishing attacks.",
      evidence_urls: ["http://localhost:8000/evidence/llm_reasoning_456"],
      timestamp: Date.now() / 1000
    },
    virustotal: {
      score: 0.75,
      confidence: 0.95,
      weight: 0.15,
      explanation: "6 out of 84 security vendors flagged this URL as malicious or suspicious.",
      evidence_urls: ["http://localhost:8000/evidence/virustotal_789"],
      timestamp: Date.now() / 1000
    },
    abuseipdb: {
      score: 0.68,
      confidence: 0.78,
      weight: 0.15,
      explanation: "IP address has been reported for malicious activities with 72% confidence.",
      evidence_urls: ["http://localhost:8000/evidence/abuseipdb_101"],
      timestamp: Date.now() / 1000
    },
    redirect_analysis: {
      score: 0.82,
      confidence: 0.86,
      weight: 0.10,
      explanation: "Detected suspicious redirect chain through multiple domains attempting to evade detection.",
      evidence_urls: ["http://localhost:8000/evidence/redirects_202"],
      timestamp: Date.now() / 1000
    }
  },
  explanation: {
    primary_reasons: [
      "High ML confidence (94%) indicating phishing patterns",
      "LLM detected deceptive credential harvesting forms",
      "Multiple VirusTotal vendors flagged as malicious",
      "Suspicious redirect chain through multiple domains",
      "Domain registration patterns consistent with phishing campaigns"
    ],
    supporting_evidence: [
      {
        type: "screenshot",
        url: "http://localhost:8000/evidence/screenshot_login_page",
        description: "Screenshot showing fake login form designed to mimic legitimate service",
        metadata: { resolution: "1920x1080", timestamp: "2024-01-15T10:30:00Z" },
        component_source: "redirect_analysis",
        timestamp: Date.now() / 1000
      },
      {
        type: "redirect_chain",
        url: "http://localhost:8000/evidence/redirect_trace",
        description: "Complete redirect chain analysis showing evasion techniques",
        metadata: { hops: 4, final_domain: "suspicious-phishing-site.com" },
        component_source: "redirect_analysis",
        timestamp: Date.now() / 1000
      },
      {
        type: "ml_features",
        url: "http://localhost:8000/evidence/ml_feature_vector",
        description: "ML feature analysis showing 23 positive phishing indicators",
        metadata: { feature_count: 156, positive_indicators: 23 },
        component_source: "ml_score",
        timestamp: Date.now() / 1000
      }
    ],
    component_breakdown: "ML(25%): 0.88 * 0.25 = 0.22, LLM(20%): 0.91 * 0.20 = 0.18, VT(15%): 0.75 * 0.15 = 0.11, AbuseIPDB(15%): 0.68 * 0.15 = 0.10, Redirects(10%): 0.82 * 0.10 = 0.08, Total: 0.69 → Rule Override → 0.85",
    confidence_reasoning: "High confidence due to agreement between ML (94%) and LLM (89%) components, supported by objective VirusTotal detections. Redirect analysis adds additional confirmation.",
    recommendations: [
      "Block access to this URL immediately",
      "Add domain to organizational blacklist",
      "Alert security team for investigation",
      "Scan for similar domains in the same campaign",
      "Update threat intelligence feeds with IOCs"
    ]
  },
  analysis_id: "threat_analysis_" + Date.now(),
  timestamp: Date.now() / 1000,
  processing_time_ms: 2847,
  rule_overrides: [
    {
      rule_name: "VirusTotal High Detection",
      condition: "virustotal.positives > 5",
      triggered: true,
      original_score: 0.69,
      override_level: "malicious",
      explanation: "Rule triggered: 6 VirusTotal detections exceeded threshold of 5",
      priority: 1
    }
  ],
  quality_metrics: {
    component_count: 5,
    component_agreement: 0.87,
    coverage_score: 0.85
  }
};

// Sample configuration templates
const SAMPLE_TEMPLATES = [
  {
    id: "conservative",
    name: "Conservative",
    description: "Higher thresholds, more cautious assessment",
    config: {
      name: "Conservative Configuration",
      description: "Higher thresholds for more cautious threat assessment",
      component_weights: {
        ml_score: 0.30,
        llm_verdict: 0.25,
        virustotal: 0.20,
        abuseipdb: 0.15,
        redirect_analysis: 0.05,
        reputation_check: 0.03,
        content_analysis: 0.01,
        cloaking_detection: 0.01
      },
      threat_thresholds: {
        safe: 0.2,
        suspicious: 0.5,
        malicious: 0.8
      },
      confidence_threshold: 0.8,
      quality_thresholds: {
        min_components: 3,
        min_coverage: 0.7,
        min_agreement: 0.6
      },
      rule_conditions: [],
      is_default: false
    }
  },
  {
    id: "aggressive",
    name: "Aggressive",
    description: "Lower thresholds, more sensitive detection",
    config: {
      name: "Aggressive Configuration",
      description: "Lower thresholds for more sensitive threat detection",
      component_weights: {
        ml_score: 0.20,
        llm_verdict: 0.15,
        virustotal: 0.25,
        abuseipdb: 0.20,
        redirect_analysis: 0.10,
        reputation_check: 0.05,
        content_analysis: 0.03,
        cloaking_detection: 0.02
      },
      threat_thresholds: {
        safe: 0.4,
        suspicious: 0.6,
        malicious: 0.7
      },
      confidence_threshold: 0.6,
      quality_thresholds: {
        min_components: 2,
        min_coverage: 0.5,
        min_agreement: 0.4
      },
      rule_conditions: [],
      is_default: false
    }
  }
];

const ThreatAggregatorDemo: React.FC = () => {
  const [activeView, setActiveView] = useState<'explanation' | 'configuration'>('explanation');
  const [currentConfig, setCurrentConfig] = useState(SAMPLE_TEMPLATES[0].config);

  const handleSaveConfig = async (config: any) => {
    console.log('Saving configuration:', config);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000));
    setCurrentConfig(config);
    alert('Configuration saved successfully!');
  };

  const handleResetConfig = () => {
    setCurrentConfig(SAMPLE_TEMPLATES[0].config);
  };

  const handleLoadTemplate = (templateId: string) => {
    const template = SAMPLE_TEMPLATES.find(t => t.id === templateId);
    if (template) {
      setCurrentConfig(template.config);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">ThreatAggregator Demo</h1>
          <p className="text-gray-600">
            Comprehensive threat assessment system combining ML scores, LLM verdicts, threat intelligence, and redirect analysis
          </p>
        </div>

        {/* Navigation */}
        <div className="bg-white border border-gray-200 rounded-lg mb-6">
          <nav className="flex">
            <button
              onClick={() => setActiveView('explanation')}
              className={`flex-1 px-6 py-3 text-center font-medium ${
                activeView === 'explanation'
                  ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-500'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              Threat Explanation
            </button>
            <button
              onClick={() => setActiveView('configuration')}
              className={`flex-1 px-6 py-3 text-center font-medium ${
                activeView === 'configuration'
                  ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-500'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              Configuration Management
            </button>
          </nav>
        </div>

        {/* Content */}
        {activeView === 'explanation' ? (
          <div>
            <div className="mb-4">
              <h2 className="text-xl font-semibold text-gray-900 mb-2">Threat Analysis Results</h2>
              <p className="text-gray-600">
                Sample analysis showing how multiple components combine to produce an explainable threat assessment.
              </p>
            </div>
            <ThreatExplanationPanel 
              threatResult={SAMPLE_THREAT_RESULT}
              className="max-w-4xl"
            />
          </div>
        ) : (
          <div>
            <div className="mb-4">
              <h2 className="text-xl font-semibold text-gray-900 mb-2">Configuration Management</h2>
              <p className="text-gray-600">
                Adjust component weights, threat thresholds, and override rules to customize threat assessment behavior.
              </p>
            </div>
            <ThreatConfigurationPanel
              configuration={currentConfig}
              templates={SAMPLE_TEMPLATES}
              onSave={handleSaveConfig}
              onReset={handleResetConfig}
              onLoadTemplate={handleLoadTemplate}
              className="max-w-6xl"
            />
          </div>
        )}

        {/* Footer */}
        <div className="mt-8 text-center text-sm text-gray-500">
          <p>ThreatAggregator v1.0 - Explainable Threat Assessment System</p>
        </div>
      </div>
    </div>
  );
};

export default ThreatAggregatorDemo;
