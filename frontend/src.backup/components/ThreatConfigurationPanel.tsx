import React, { useState, useEffect } from 'react';
import { 
  Settings, 
  Save, 
  RotateCcw, 
  AlertTriangle,
  Shield,
  TrendingUp,
  FileText,
  Globe,
  Target,
  Info,
  Plus,
  Trash2,
  Edit3,
  Copy,
  Download,
  Upload
} from 'lucide-react';

interface ComponentWeight {
  ml_score: number;
  llm_verdict: number;
  virustotal: number;
  abuseipdb: number;
  redirect_analysis: number;
  reputation_check: number;
  content_analysis: number;
  cloaking_detection: number;
}

interface ThreatThresholds {
  safe: number;
  suspicious: number;
  malicious: number;
}

interface RuleCondition {
  id: string;
  name: string;
  condition: string;
  override_level: 'safe' | 'suspicious' | 'malicious';
  priority: number;
  enabled: boolean;
  description: string;
}

interface ThreatConfiguration {
  id?: string;
  name: string;
  description: string;
  tenant_id?: string;
  component_weights: ComponentWeight;
  threat_thresholds: ThreatThresholds;
  confidence_threshold: number;
  quality_thresholds: {
    min_components: number;
    min_coverage: number;
    min_agreement: number;
  };
  rule_conditions: RuleCondition[];
  is_default: boolean;
  created_at?: string;
  updated_at?: string;
}

interface ConfigurationTemplate {
  id: string;
  name: string;
  description: string;
  config: ThreatConfiguration;
}

interface ThreatConfigurationPanelProps {
  configuration?: ThreatConfiguration;
  templates?: ConfigurationTemplate[];
  onSave: (config: ThreatConfiguration) => Promise<void>;
  onReset: () => void;
  onLoadTemplate: (templateId: string) => void;
  className?: string;
}

const DEFAULT_CONFIGURATION: ThreatConfiguration = {
  name: "Default Configuration",
  description: "Standard threat assessment configuration",
  component_weights: {
    ml_score: 0.25,
    llm_verdict: 0.20,
    virustotal: 0.15,
    abuseipdb: 0.15,
    redirect_analysis: 0.10,
    reputation_check: 0.10,
    content_analysis: 0.03,
    cloaking_detection: 0.02
  },
  threat_thresholds: {
    safe: 0.3,
    suspicious: 0.6,
    malicious: 0.8
  },
  confidence_threshold: 0.7,
  quality_thresholds: {
    min_components: 2,
    min_coverage: 0.6,
    min_agreement: 0.5
  },
  rule_conditions: [
    {
      id: "vt_high_detection",
      name: "VirusTotal High Detection",
      condition: "virustotal.positives > 5",
      override_level: "malicious",
      priority: 1,
      enabled: true,
      description: "Override to malicious if VirusTotal shows >5 positive detections"
    },
    {
      id: "abuseipdb_confirmed",
      name: "AbuseIPDB Confirmed Malicious",
      condition: "abuseipdb.confidence > 90 AND abuseipdb.is_malicious = true",
      override_level: "malicious",
      priority: 2,
      enabled: true,
      description: "Override to malicious if AbuseIPDB confirms with >90% confidence"
    },
    {
      id: "ml_high_confidence",
      name: "ML High Confidence Safe",
      condition: "ml_score.score < 0.1 AND ml_score.confidence > 0.95",
      override_level: "safe",
      priority: 10,
      enabled: true,
      description: "Override to safe if ML is very confident (>95%) about low threat"
    }
  ],
  is_default: false
};

const ThreatConfigurationPanel: React.FC<ThreatConfigurationPanelProps> = ({
  configuration = DEFAULT_CONFIGURATION,
  templates = [],
  onSave,
  onReset,
  onLoadTemplate,
  className = ''
}) => {
  const [config, setConfig] = useState<ThreatConfiguration>(configuration);
  const [activeTab, setActiveTab] = useState<'weights' | 'thresholds' | 'rules' | 'quality'>('weights');
  const [editingRule, setEditingRule] = useState<string | null>(null);
  const [newRule, setNewRule] = useState<RuleCondition | null>(null);
  const [hasChanges, setHasChanges] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    setConfig(configuration);
    setHasChanges(false);
  }, [configuration]);

  const updateConfig = (updates: Partial<ThreatConfiguration>) => {
    setConfig(prev => ({ ...prev, ...updates }));
    setHasChanges(true);
  };

  const updateComponentWeight = (component: keyof ComponentWeight, weight: number) => {
    setConfig(prev => ({
      ...prev,
      component_weights: {
        ...prev.component_weights,
        [component]: weight
      }
    }));
    setHasChanges(true);
  };

  const updateThreshold = (level: keyof ThreatThresholds, value: number) => {
    setConfig(prev => ({
      ...prev,
      threat_thresholds: {
        ...prev.threat_thresholds,
        [level]: value
      }
    }));
    setHasChanges(true);
  };

  const addRule = () => {
    const rule: RuleCondition = {
      id: `rule_${Date.now()}`,
      name: "New Rule",
      condition: "component.score > 0.8",
      override_level: "malicious",
      priority: config.rule_conditions.length + 1,
      enabled: true,
      description: "New rule description"
    };
    setNewRule(rule);
    setEditingRule(rule.id);
  };

  const saveRule = (rule: RuleCondition) => {
    if (newRule && rule.id === newRule.id) {
      setConfig(prev => ({
        ...prev,
        rule_conditions: [...prev.rule_conditions, rule]
      }));
      setNewRule(null);
    } else {
      setConfig(prev => ({
        ...prev,
        rule_conditions: prev.rule_conditions.map(r => r.id === rule.id ? rule : r)
      }));
    }
    setEditingRule(null);
    setHasChanges(true);
  };

  const deleteRule = (ruleId: string) => {
    setConfig(prev => ({
      ...prev,
      rule_conditions: prev.rule_conditions.filter(r => r.id !== ruleId)
    }));
    setHasChanges(true);
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await onSave(config);
      setHasChanges(false);
    } catch (error) {
      console.error('Failed to save configuration:', error);
    } finally {
      setIsSaving(false);
    }
  };

  const handleReset = () => {
    onReset();
    setHasChanges(false);
    setEditingRule(null);
    setNewRule(null);
  };

  const getComponentIcon = (component: string) => {
    switch (component) {
      case 'ml_score': return <TrendingUp className="w-4 h-4" />;
      case 'llm_verdict': return <FileText className="w-4 h-4" />;
      case 'virustotal': return <Shield className="w-4 h-4" />;
      case 'abuseipdb': return <Globe className="w-4 h-4" />;
      case 'redirect_analysis': return <Target className="w-4 h-4" />;
      default: return <Info className="w-4 h-4" />;
    }
  };

  const formatComponentName = (component: string) => {
    const names: Record<string, string> = {
      'ml_score': 'ML Analysis',
      'llm_verdict': 'LLM Verdict',
      'virustotal': 'VirusTotal',
      'abuseipdb': 'AbuseIPDB',
      'redirect_analysis': 'Redirect Analysis',
      'reputation_check': 'Reputation Check',
      'content_analysis': 'Content Analysis',
      'cloaking_detection': 'Cloaking Detection'
    };
    return names[component] || component.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  const Slider = ({ 
    label, 
    value, 
    min = 0, 
    max = 1, 
    step = 0.01, 
    onChange, 
    icon 
  }: {
    label: string;
    value: number;
    min?: number;
    max?: number;
    step?: number;
    onChange: (value: number) => void;
    icon?: React.ReactNode;
  }) => (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          {icon}
          <label className="text-sm font-medium text-gray-700">{label}</label>
        </div>
        <span className="text-sm text-gray-600">{(value * 100).toFixed(0)}%</span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
      />
    </div>
  );

  const RuleEditor = ({ rule, onSave, onCancel }: {
    rule: RuleCondition;
    onSave: (rule: RuleCondition) => void;
    onCancel: () => void;
  }) => {
    const [editedRule, setEditedRule] = useState(rule);

    return (
      <div className="border border-blue-200 bg-blue-50 rounded-lg p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Rule Name</label>
            <input
              type="text"
              value={editedRule.name}
              onChange={(e) => setEditedRule(prev => ({ ...prev, name: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Override Level</label>
            <select
              value={editedRule.override_level}
              onChange={(e) => setEditedRule(prev => ({ ...prev, override_level: e.target.value as any }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
            >
              <option value="safe">Safe</option>
              <option value="suspicious">Suspicious</option>
              <option value="malicious">Malicious</option>
            </select>
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Condition</label>
          <input
            type="text"
            value={editedRule.condition}
            onChange={(e) => setEditedRule(prev => ({ ...prev, condition: e.target.value }))}
            className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm font-mono"
            placeholder="e.g., virustotal.positives > 5"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
          <textarea
            value={editedRule.description}
            onChange={(e) => setEditedRule(prev => ({ ...prev, description: e.target.value }))}
            className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
            rows={2}
          />
        </div>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={editedRule.enabled}
                onChange={(e) => setEditedRule(prev => ({ ...prev, enabled: e.target.checked }))}
                className="rounded"
              />
              <span className="text-sm text-gray-700">Enabled</span>
            </label>
            <div className="flex items-center space-x-2">
              <label className="text-sm text-gray-700">Priority:</label>
              <input
                type="number"
                value={editedRule.priority}
                onChange={(e) => setEditedRule(prev => ({ ...prev, priority: parseInt(e.target.value) }))}
                className="w-16 px-2 py-1 border border-gray-300 rounded text-sm"
                min="1"
              />
            </div>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => onSave(editedRule)}
              className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
            >
              Save
            </button>
            <button
              onClick={onCancel}
              className="px-3 py-1 bg-gray-300 text-gray-700 rounded text-sm hover:bg-gray-400"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className={`bg-white border border-gray-200 rounded-lg shadow-sm ${className}`}>
      {/* Header */}
      <div className="border-b border-gray-200 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Settings className="w-6 h-6 text-blue-600" />
            <div>
              <h2 className="text-xl font-bold text-gray-900">Threat Configuration</h2>
              <p className="text-sm text-gray-600">{config.name} - {config.description}</p>
            </div>
          </div>
          <div className="flex space-x-2">
            {templates.length > 0 && (
              <select
                onChange={(e) => e.target.value && onLoadTemplate(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-md text-sm"
                value=""
              >
                <option value="">Load Template...</option>
                {templates.map(template => (
                  <option key={template.id} value={template.id}>
                    {template.name}
                  </option>
                ))}
              </select>
            )}
            <button
              onClick={handleReset}
              className="px-3 py-2 bg-gray-300 text-gray-700 rounded-md text-sm hover:bg-gray-400 flex items-center space-x-1"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Reset</span>
            </button>
            <button
              onClick={handleSave}
              disabled={!hasChanges || isSaving}
              className="px-3 py-2 bg-blue-600 text-white rounded-md text-sm hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-1"
            >
              <Save className="w-4 h-4" />
              <span>{isSaving ? 'Saving...' : 'Save Changes'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex space-x-8 px-4">
          {[
            { id: 'weights', label: 'Component Weights', icon: <TrendingUp className="w-4 h-4" /> },
            { id: 'thresholds', label: 'Threat Thresholds', icon: <AlertTriangle className="w-4 h-4" /> },
            { id: 'rules', label: 'Override Rules', icon: <Shield className="w-4 h-4" /> },
            { id: 'quality', label: 'Quality Settings', icon: <Target className="w-4 h-4" /> }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center space-x-2 py-3 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="p-4">
        {activeTab === 'weights' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Component Weights</h3>
              <p className="text-sm text-gray-600 mb-4">
                Adjust the relative importance of each component in the final threat score calculation.
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {Object.entries(config.component_weights).map(([component, weight]) => (
                <Slider
                  key={component}
                  label={formatComponentName(component)}
                  value={weight}
                  onChange={(value) => updateComponentWeight(component as keyof ComponentWeight, value)}
                  icon={getComponentIcon(component)}
                />
              ))}
            </div>
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <h4 className="font-medium text-blue-900 mb-2">Weight Distribution</h4>
              <div className="text-sm text-blue-800">
                Total: {(Object.values(config.component_weights).reduce((a, b) => a + b, 0) * 100).toFixed(1)}%
                {Math.abs(Object.values(config.component_weights).reduce((a, b) => a + b, 0) - 1) > 0.01 && (
                  <span className="ml-2 text-orange-600 font-medium">
                    ⚠ Weights should sum to 100%
                  </span>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'thresholds' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Level Thresholds</h3>
              <p className="text-sm text-gray-600 mb-4">
                Set the score thresholds that determine threat level classifications.
              </p>
            </div>
            <div className="space-y-4">
              <Slider
                label="Safe Threshold (below this = safe)"
                value={config.threat_thresholds.safe}
                onChange={(value) => updateThreshold('safe', value)}
                icon={<Shield className="w-4 h-4 text-green-600" />}
              />
              <Slider
                label="Suspicious Threshold (above safe, below this = suspicious)"
                value={config.threat_thresholds.suspicious}
                onChange={(value) => updateThreshold('suspicious', value)}
                icon={<AlertTriangle className="w-4 h-4 text-orange-600" />}
              />
              <Slider
                label="Malicious Threshold (above this = malicious)"
                value={config.threat_thresholds.malicious}
                onChange={(value) => updateThreshold('malicious', value)}
                icon={<Shield className="w-4 h-4 text-red-600" />}
              />
            </div>
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
              <h4 className="font-medium text-gray-900 mb-2">Threshold Visualization</h4>
              <div className="flex items-center space-x-2">
                <div className="flex-1 bg-gradient-to-r from-green-200 via-orange-200 to-red-200 h-8 rounded-lg relative">
                  <div 
                    className="absolute top-0 bottom-0 w-1 bg-green-600"
                    style={{ left: `${config.threat_thresholds.safe * 100}%` }}
                  />
                  <div 
                    className="absolute top-0 bottom-0 w-1 bg-orange-600"
                    style={{ left: `${config.threat_thresholds.suspicious * 100}%` }}
                  />
                  <div 
                    className="absolute top-0 bottom-0 w-1 bg-red-600"
                    style={{ left: `${config.threat_thresholds.malicious * 100}%` }}
                  />
                </div>
              </div>
              <div className="flex justify-between text-xs text-gray-600 mt-1">
                <span>0% (Safe)</span>
                <span>50%</span>
                <span>100% (Malicious)</span>
              </div>
            </div>
            <div>
              <Slider
                label="Confidence Threshold (minimum confidence for assessment)"
                value={config.confidence_threshold}
                onChange={(value) => updateConfig({ confidence_threshold: value })}
                icon={<Target className="w-4 h-4 text-blue-600" />}
              />
            </div>
          </div>
        )}

        {activeTab === 'rules' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Override Rules</h3>
                <p className="text-sm text-gray-600">
                  Define conditions that can override the calculated threat score.
                </p>
              </div>
              <button
                onClick={addRule}
                className="px-3 py-2 bg-blue-600 text-white rounded-md text-sm hover:bg-blue-700 flex items-center space-x-1"
              >
                <Plus className="w-4 h-4" />
                <span>Add Rule</span>
              </button>
            </div>

            <div className="space-y-4">
              {newRule && editingRule === newRule.id && (
                <RuleEditor
                  rule={newRule}
                  onSave={saveRule}
                  onCancel={() => {
                    setNewRule(null);
                    setEditingRule(null);
                  }}
                />
              )}

              {config.rule_conditions.map((rule) => (
                <div key={rule.id}>
                  {editingRule === rule.id ? (
                    <RuleEditor
                      rule={rule}
                      onSave={saveRule}
                      onCancel={() => setEditingRule(null)}
                    />
                  ) : (
                    <div className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-3">
                          <div className={`w-3 h-3 rounded-full ${
                            rule.enabled ? 'bg-green-500' : 'bg-gray-400'
                          }`} />
                          <span className="font-medium text-gray-900">{rule.name}</span>
                          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                            rule.override_level === 'malicious' ? 'bg-red-100 text-red-800' :
                            rule.override_level === 'suspicious' ? 'bg-orange-100 text-orange-800' :
                            'bg-green-100 text-green-800'
                          }`}>
                            {rule.override_level}
                          </span>
                          <span className="text-xs text-gray-500">Priority: {rule.priority}</span>
                        </div>
                        <div className="flex space-x-2">
                          <button
                            onClick={() => setEditingRule(rule.id)}
                            className="p-1 text-gray-400 hover:text-gray-600"
                          >
                            <Edit3 className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => deleteRule(rule.id)}
                            className="p-1 text-red-400 hover:text-red-600"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                      <p className="text-sm text-gray-600 mb-2">{rule.description}</p>
                      <code className="text-xs bg-gray-100 px-2 py-1 rounded font-mono text-gray-800">
                        {rule.condition}
                      </code>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'quality' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Quality Control Settings</h3>
              <p className="text-sm text-gray-600 mb-4">
                Configure minimum quality requirements for threat assessments.
              </p>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Minimum Components</label>
                <input
                  type="number"
                  value={config.quality_thresholds.min_components}
                  onChange={(e) => updateConfig({
                    quality_thresholds: {
                      ...config.quality_thresholds,
                      min_components: parseInt(e.target.value)
                    }
                  })}
                  className="w-24 px-3 py-2 border border-gray-300 rounded-md text-sm"
                  min="1"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Minimum number of components required for a valid assessment
                </p>
              </div>

              <Slider
                label="Minimum Coverage Score"
                value={config.quality_thresholds.min_coverage}
                onChange={(value) => updateConfig({
                  quality_thresholds: {
                    ...config.quality_thresholds,
                    min_coverage: value
                  }
                })}
                icon={<Target className="w-4 h-4 text-blue-600" />}
              />

              <Slider
                label="Minimum Component Agreement"
                value={config.quality_thresholds.min_agreement}
                onChange={(value) => updateConfig({
                  quality_thresholds: {
                    ...config.quality_thresholds,
                    min_agreement: value
                  }
                })}
                icon={<Shield className="w-4 h-4 text-purple-600" />}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatConfigurationPanel;
