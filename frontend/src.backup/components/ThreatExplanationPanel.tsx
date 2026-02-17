import React, { useState } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  ExternalLink, 
  ChevronDown, 
  ChevronUp,
  Info,
  Target,
  Clock,
  TrendingUp,
  Eye,
  FileText,
  Globe
} from 'lucide-react';
import { SecureText, SecureContent, SecureList } from './SecureContentRenderer';

interface ComponentScore {
  score: number;
  confidence: number;
  weight: number;
  explanation: string;
  evidence_urls: string[];
  timestamp: number;
}

interface Evidence {
  type: string;
  url: string;
  description: string;
  metadata: Record<string, any>;
  component_source?: string;
  timestamp: number;
}

interface ThreatExplanation {
  primary_reasons: string[];
  supporting_evidence: Evidence[];
  component_breakdown: string;
  confidence_reasoning: string;
  recommendations: string[];
}

interface RuleOverride {
  rule_name: string;
  condition: string;
  triggered: boolean;
  original_score: number;
  override_level: string;
  explanation: string;
  priority: number;
}

interface ThreatResult {
  target: string;
  target_type: string;
  score: number;
  level: 'safe' | 'suspicious' | 'malicious';
  confidence: number;
  components: Record<string, ComponentScore>;
  explanation: ThreatExplanation;
  analysis_id: string;
  timestamp: number;
  processing_time_ms: number;
  rule_overrides: RuleOverride[];
  quality_metrics: {
    component_count: number;
    component_agreement: number;
    coverage_score: number;
  };
}

interface ThreatExplanationPanelProps {
  threatResult: ThreatResult;
  className?: string;
}

const ThreatExplanationPanel: React.FC<ThreatExplanationPanelProps> = ({ 
  threatResult, 
  className = '' 
}) => {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['overview']));

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(section)) {
        newSet.delete(section);
      } else {
        newSet.add(section);
      }
      return newSet;
    });
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'malicious': return 'text-red-600 bg-red-50 border-red-200';
      case 'suspicious': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'safe': return 'text-green-600 bg-green-50 border-green-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'malicious': return <Shield className="w-5 h-5 text-red-600" />;
      case 'suspicious': return <AlertTriangle className="w-5 h-5 text-orange-600" />;
      case 'safe': return <CheckCircle className="w-5 h-5 text-green-600" />;
      default: return <Info className="w-5 h-5 text-gray-600" />;
    }
  };

  const getComponentIcon = (componentType: string) => {
    switch (componentType) {
      case 'ml_score': return <TrendingUp className="w-4 h-4" />;
      case 'llm_verdict': return <FileText className="w-4 h-4" />;
      case 'virustotal': return <Shield className="w-4 h-4" />;
      case 'abuseipdb': return <Globe className="w-4 h-4" />;
      case 'redirect_analysis': return <Target className="w-4 h-4" />;
      default: return <Info className="w-4 h-4" />;
    }
  };

  const formatComponentName = (componentType: string) => {
    const names: Record<string, string> = {
      'ml_score': 'ML Analysis',
      'llm_verdict': 'LLM Verdict',
      'virustotal': 'VirusTotal',
      'abuseipdb': 'AbuseIPDB',
      'redirect_analysis': 'Redirect Analysis',
      'cloaking_detection': 'Cloaking Detection',
      'content_analysis': 'Content Analysis',
      'reputation_check': 'Reputation Check'
    };
    return names[componentType] || componentType.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  const formatEvidenceType = (evidenceType: string) => {
    const types: Record<string, string> = {
      'screenshot': 'Screenshot',
      'redirect_chain': 'Redirect Chain',
      'network_log': 'Network Log',
      'reputation_data': 'Reputation Data',
      'ml_features': 'ML Features',
      'llm_reasoning': 'LLM Reasoning',
      'behavioral_analysis': 'Behavioral Analysis'
    };
    return types[evidenceType] || evidenceType.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  const ScoreBar = ({ score, label, color = 'blue' }: { score: number; label: string; color?: string }) => (
    <div className="flex items-center space-x-2">
      <span className="text-sm font-medium text-gray-700 min-w-20">{label}:</span>
      <div className="flex-1 bg-gray-200 rounded-full h-2">
        <div 
          className={`h-2 rounded-full`}
          style={{ 
            width: `${score * 100}%`,
            backgroundColor: color === 'red' ? '#ef4444' : color === 'orange' ? '#f97316' : color === 'green' ? '#22c55e' : '#3b82f6'
          }}
        />
      </div>
      <span className="text-sm text-gray-600 min-w-12">{(score * 100).toFixed(0)}%</span>
    </div>
  );

  return (
    <div className={`bg-white border border-gray-200 rounded-lg shadow-sm ${className}`}>
      {/* Header */}
      <div className="border-b border-gray-200 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {getThreatIcon(threatResult.level)}
            <div>
              <h2 className="text-xl font-bold text-gray-900">Threat Analysis Explanation</h2>
              <p className="text-sm text-gray-600">Analysis ID: {threatResult.analysis_id}</p>
            </div>
          </div>
          <div className={`px-3 py-1 rounded-full border ${getThreatLevelColor(threatResult.level)}`}>
            <span className="text-sm font-medium capitalize">{threatResult.level}</span>
          </div>
        </div>
      </div>

      {/* Overview Section */}
      <div className="border-b border-gray-200">
        <button
          onClick={() => toggleSection('overview')}
          className="w-full flex items-center justify-between p-3 hover:bg-gray-50 rounded-lg"
        >
          <div className="flex items-center space-x-2">
            <Target className="w-5 h-5" />
            <h3 className="text-lg font-semibold text-gray-900">Threat Overview</h3>
          </div>
          {expandedSections.has('overview') ? 
            <ChevronUp className="w-5 h-5 text-gray-500" /> : 
            <ChevronDown className="w-5 h-5 text-gray-500" />
          }
        </button>
        {expandedSections.has('overview') && (
          <div className="p-4 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <ScoreBar 
                  score={threatResult.score} 
                  label="Threat Score" 
                  color={threatResult.level === 'malicious' ? 'red' : threatResult.level === 'suspicious' ? 'orange' : 'green'}
                />
                <ScoreBar 
                  score={threatResult.confidence} 
                  label="Confidence" 
                  color="blue"
                />
                <ScoreBar 
                  score={threatResult.quality_metrics.coverage_score} 
                  label="Coverage" 
                  color="purple"
                />
              </div>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Target:</span>
                  <span className="text-sm font-medium text-gray-900 break-all max-w-xs">{threatResult.target}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Type:</span>
                  <span className="text-sm font-medium text-gray-900">{threatResult.target_type}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Components:</span>
                  <span className="text-sm font-medium text-gray-900">{threatResult.quality_metrics.component_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Processing Time:</span>
                  <span className="text-sm font-medium text-gray-900">{threatResult.processing_time_ms}ms</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Primary Reasons Section */}
      <div className="border-b border-gray-200">
        <button
          onClick={() => toggleSection('reasons')}
          className="w-full flex items-center justify-between p-3 hover:bg-gray-50 rounded-lg"
        >
          <div className="flex items-center space-x-2">
            <Info className="w-5 h-5" />
            <h3 className="text-lg font-semibold text-gray-900">Primary Reasons</h3>
            <span className="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
              {threatResult.explanation.primary_reasons.length}
            </span>
          </div>
          {expandedSections.has('reasons') ? 
            <ChevronUp className="w-5 h-5 text-gray-500" /> : 
            <ChevronDown className="w-5 h-5 text-gray-500" />
          }
        </button>
        {expandedSections.has('reasons') && (
          <div className="p-4">
            <ul className="space-y-2">
              {threatResult.explanation.primary_reasons.map((reason, index) => (
                <li key={index} className="flex items-start space-x-2">
                  <span className="text-blue-500 text-lg">•</span>
                  <SecureText 
                    content={reason} 
                    className="text-gray-900"
                    maxLength={500}
                    testId={`threat-reason-${index}`}
                  />
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Component Analysis Section */}
      <div className="border-b border-gray-200">
        <button
          onClick={() => toggleSection('components')}
          className="w-full flex items-center justify-between p-3 hover:bg-gray-50 rounded-lg"
        >
          <div className="flex items-center space-x-2">
            <TrendingUp className="w-5 h-5" />
            <h3 className="text-lg font-semibold text-gray-900">Component Analysis</h3>
            <span className="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
              {Object.keys(threatResult.components).length}
            </span>
          </div>
          {expandedSections.has('components') ? 
            <ChevronUp className="w-5 h-5 text-gray-500" /> : 
            <ChevronDown className="w-5 h-5 text-gray-500" />
          }
        </button>
        {expandedSections.has('components') && (
          <div className="p-4 space-y-4">
            {Object.entries(threatResult.components).map(([componentType, component]) => (
              <div key={componentType} className="border border-gray-200 rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    {getComponentIcon(componentType)}
                    <span className="font-medium text-gray-900">
                      {formatComponentName(componentType)}
                    </span>
                  </div>
                  <span className="text-sm text-gray-600">
                    Weight: {(component.weight * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="space-y-2">
                  <ScoreBar 
                    score={component.score} 
                    label="Score" 
                    color={component.score > 0.7 ? 'red' : component.score > 0.4 ? 'orange' : 'green'}
                  />
                  <ScoreBar 
                    score={component.confidence} 
                    label="Confidence" 
                    color="blue"
                  />
                  <SecureText 
                    content={component.explanation} 
                    className="text-sm text-gray-700 mt-2"
                    maxLength={1000}
                    testId={`component-explanation-${componentType}`}
                  />
                  {component.evidence_urls.length > 0 && (
                    <div className="flex flex-wrap gap-2 mt-2">
                      {component.evidence_urls.map((url, index) => (
                        <a
                          key={index}
                          href={url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center space-x-1 text-blue-600 hover:text-blue-800 text-sm"
                        >
                          <span>Evidence {index + 1}</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recommendations Section */}
      <div className="border-b border-gray-200">
        <button
          onClick={() => toggleSection('recommendations')}
          className="w-full flex items-center justify-between p-3 hover:bg-gray-50 rounded-lg"
        >
          <div className="flex items-center space-x-2">
            <CheckCircle className="w-5 h-5" />
            <h3 className="text-lg font-semibold text-gray-900">Recommendations</h3>
            <span className="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
              {threatResult.explanation.recommendations.length}
            </span>
          </div>
          {expandedSections.has('recommendations') ? 
            <ChevronUp className="w-5 h-5 text-gray-500" /> : 
            <ChevronDown className="w-5 h-5 text-gray-500" />
          }
        </button>
        {expandedSections.has('recommendations') && (
          <div className="p-4">
            <ul className="space-y-2">
              {threatResult.explanation.recommendations.map((recommendation, index) => (
                <li key={index} className="flex items-start space-x-2">
                  <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                  <SecureText 
                    content={recommendation} 
                    className="text-gray-900"
                    maxLength={800}
                    testId={`recommendation-${index}`}
                  />
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Technical Details Section */}
      <div>
        <button
          onClick={() => toggleSection('technical')}
          className="w-full flex items-center justify-between p-3 hover:bg-gray-50 rounded-lg"
        >
          <div className="flex items-center space-x-2">
            <Clock className="w-5 h-5" />
            <h3 className="text-lg font-semibold text-gray-900">Technical Details</h3>
          </div>
          {expandedSections.has('technical') ? 
            <ChevronUp className="w-5 h-5 text-gray-500" /> : 
            <ChevronDown className="w-5 h-5 text-gray-500" />
          }
        </button>
        {expandedSections.has('technical') && (
          <div className="p-4 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="font-medium text-gray-900 mb-2">Quality Metrics</h4>
                <div className="space-y-1 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Component Agreement:</span>
                    <span className="font-medium">{(threatResult.quality_metrics.component_agreement * 100).toFixed(1)}%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Coverage Score:</span>
                    <span className="font-medium">{(threatResult.quality_metrics.coverage_score * 100).toFixed(1)}%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Component Count:</span>
                    <span className="font-medium">{threatResult.quality_metrics.component_count}</span>
                  </div>
                </div>
              </div>
              <div>
                <h4 className="font-medium text-gray-900 mb-2">Analysis Details</h4>
                <div className="space-y-1 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Timestamp:</span>
                    <span className="font-medium">{new Date(threatResult.timestamp * 1000).toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Processing Time:</span>
                    <span className="font-medium">{threatResult.processing_time_ms}ms</span>
                  </div>
                </div>
              </div>
            </div>
            <div>
              <h4 className="font-medium text-gray-900 mb-2">Component Breakdown</h4>
              <SecureText 
                content={threatResult.explanation.component_breakdown}
                className="text-sm text-gray-700 bg-gray-50 p-3 rounded-lg font-mono block"
                maxLength={2000}
                testId="component-breakdown"
              />
            </div>
            <div>
              <h4 className="font-medium text-gray-900 mb-2">Confidence Reasoning</h4>
              <SecureText 
                content={threatResult.explanation.confidence_reasoning}
                className="text-sm text-gray-700"
                maxLength={1500}
                testId="confidence-reasoning"
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatExplanationPanel;
