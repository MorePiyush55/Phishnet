import React, { useState, useEffect } from 'react';
import { ThreatExplanationDashboard } from '@/components/threat/ThreatExplanationDashboard';
import { useThreatAnalysis, useAnalysisComparison } from '@/hooks/useThreatAnalysis';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  Play, 
  History, 
  Settings, 
  RefreshCw, 
  Compare,
  Check,
  AlertTriangle
} from 'lucide-react';

// Mock data for demonstration
const mockThreatAnalysis = {
  threat_score: 0.87,
  threat_level: 'high',
  recommended_action: 'quarantine',
  deterministic_hash: 'sha256:a7f3c9d8e2b1f4c5a8d6e9f2b3c7a1e4d8f5b2c9e6a3d7f1b4c8e5a2d9f6b3c',
  explanation: {
    reasoning: 'Multiple high-confidence indicators suggest this email is a sophisticated phishing attempt targeting financial credentials. The combination of URL obfuscation, sender spoofing, and urgency tactics creates a high threat profile.',
    confidence_band: {
      lower_bound: 0.82,
      upper_bound: 0.93,
      confidence_level: 0.95
    },
    top_signals: [
      {
        name: 'suspicious_url_redirect',
        description: 'URL redirects through multiple suspicious domains',
        component: 'url_analyzer',
        contribution: 0.34,
        evidence: [
          'URL contains 3 redirect hops through unverified domains',
          'Final destination mimics legitimate banking site',
          'HTTPS certificate is recently issued and suspicious'
        ]
      },
      {
        name: 'sender_domain_spoofing',
        description: 'Sender domain impersonates trusted financial institution',
        component: 'sender_analyzer',
        contribution: 0.28,
        evidence: [
          'From domain "bankofamerica-security.info" mimics legitimate "bankofamerica.com"',
          'SPF record does not authorize sending server',
          'DKIM signature validation failed'
        ]
      },
      {
        name: 'urgency_language_patterns',
        description: 'Content contains high-pressure urgency tactics',
        component: 'content_analyzer',
        contribution: 0.25,
        evidence: [
          'Contains phrases like "immediate action required" and "account suspended"',
          'Multiple deadline references within 24 hours',
          'Emotional manipulation language detected'
        ]
      }
    ],
    component_breakdown: {
      url_analyzer: 0.91,
      sender_analyzer: 0.85,
      content_analyzer: 0.78,
      attachment_analyzer: 0.12,
      reputation_analyzer: 0.89,
      behavioral_analyzer: 0.67,
      ml_classifier: 0.93,
      header_analyzer: 0.74
    },
    certainty_factors: {
      component_agreement: 0.89,
      data_coverage: 0.95,
      signal_strength: 0.87,
      confidence_consistency: 0.92
    },
    risk_factors: [
      'Financial credential harvesting',
      'Domain spoofing',
      'URL obfuscation',
      'Social engineering tactics',
      'Recent threat intelligence match'
    ]
  },
  components: [
    {
      type: 'url_analyzer',
      score: 0.91,
      confidence: 0.96,
      signals: ['redirect_chain', 'suspicious_tld', 'domain_age', 'ssl_certificate', 'url_shortening'],
      processing_time: 0.142
    },
    {
      type: 'ml_classifier',
      score: 0.93,
      confidence: 0.91,
      signals: ['text_features', 'structural_patterns', 'linguistic_analysis', 'ensemble_prediction'],
      processing_time: 0.387
    },
    {
      type: 'reputation_analyzer',
      score: 0.89,
      confidence: 0.88,
      signals: ['sender_reputation', 'domain_reputation', 'ip_reputation', 'threat_intelligence'],
      processing_time: 0.234
    },
    {
      type: 'sender_analyzer',
      score: 0.85,
      confidence: 0.94,
      signals: ['spf_validation', 'dkim_signature', 'dmarc_policy', 'sender_patterns'],
      processing_time: 0.098
    },
    {
      type: 'content_analyzer',
      score: 0.78,
      confidence: 0.82,
      signals: ['urgency_patterns', 'credential_requests', 'social_engineering', 'language_analysis'],
      processing_time: 0.156
    },
    {
      type: 'header_analyzer',
      score: 0.74,
      confidence: 0.85,
      signals: ['routing_anomalies', 'header_spoofing', 'timestamp_analysis', 'server_patterns'],
      processing_time: 0.067
    },
    {
      type: 'behavioral_analyzer',
      score: 0.67,
      confidence: 0.73,
      signals: ['user_interaction', 'timing_patterns', 'frequency_analysis', 'context_awareness'],
      processing_time: 0.203
    },
    {
      type: 'attachment_analyzer',
      score: 0.12,
      confidence: 0.95,
      signals: ['no_attachments_detected'],
      processing_time: 0.045
    }
  ],
  metadata: {
    threshold_profile: 'balanced',
    processing_time: 1.332,
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  }
};

const sampleEmails = {
  phishing: `From: security@bankofamerica-security.info
To: customer@email.com
Subject: URGENT: Account Security Alert - Immediate Action Required

Dear Valued Customer,

We have detected suspicious activity on your Bank of America account. Your account will be suspended within 24 hours unless you verify your information immediately.

Click here to secure your account: https://bit.ly/3xYz9Qw

This is a time-sensitive matter. Please act now to prevent account closure.

Best regards,
Bank of America Security Team`,

  legitimate: `From: notifications@bankofamerica.com
To: customer@email.com
Subject: Monthly Statement Available

Dear Customer,

Your monthly statement for account ending in 1234 is now available in online banking.

Log in to your account at https://www.bankofamerica.com to view your statement.

If you have questions, please contact customer service at 1-800-432-1000.

Thank you for banking with us.

Bank of America`,

  spam: `From: deals@amazingoffers.com
To: customer@email.com
Subject: You've Won $1,000,000!

Congratulations! You have been selected as our grand prize winner!

Claim your prize now by clicking here: https://winbig.lottery-prizes.net

This offer expires in 48 hours. Don't miss out on your million-dollar prize!

Act fast and claim your winnings today!

Lucky Lottery Commission`
};

export default function ThreatAnalysisTestPage() {
  const [emailContent, setEmailContent] = useState('');
  const [selectedSample, setSelectedSample] = useState<string>('');
  const [thresholdProfile, setThresholdProfile] = useState<'strict' | 'balanced' | 'lenient'>('balanced');
  const [showComparison, setShowComparison] = useState(false);
  
  const { 
    data, 
    loading, 
    error, 
    analyzeEmail, 
    clearError,
    clearData 
  } = useThreatAnalysis();
  
  const { 
    baseline, 
    comparisons, 
    setBaseline, 
    addComparison, 
    clearComparisons,
    calculateDifferences 
  } = useAnalysisComparison();

  // Use mock data if no real analysis is available
  const displayData = data || mockThreatAnalysis;

  const handleSampleSelect = (sampleKey: string) => {
    setSelectedSample(sampleKey);
    setEmailContent(sampleEmails[sampleKey as keyof typeof sampleEmails]);
  };

  const handleAnalyze = async () => {
    if (!emailContent.trim()) {
      return;
    }

    clearError();
    await analyzeEmail(emailContent, {
      threshold_profile: thresholdProfile,
      include_explanation: true
    });
  };

  const handleCompareAnalysis = () => {
    if (data) {
      if (!baseline) {
        setBaseline(data);
      } else {
        addComparison(data);
      }
    }
  };

  const differences = calculateDifferences();

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 space-y-8">
        {/* Header */}
        <div className="text-center">
          <h1 className="text-3xl font-bold text-gray-900">Threat Analysis Explanation System</h1>
          <p className="text-gray-600 mt-2">
            Test the deterministic threat scoring and explainability features
          </p>
        </div>

        {/* Analysis Input Panel */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Settings className="h-5 w-5" />
              <span>Email Analysis Configuration</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Sample Email Selection */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-sm font-medium">Sample Emails</label>
                <Select value={selectedSample} onValueChange={handleSampleSelect}>
                  <SelectTrigger>
                    <SelectValue placeholder="Choose a sample email" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="phishing">Phishing Email</SelectItem>
                    <SelectItem value="legitimate">Legitimate Email</SelectItem>
                    <SelectItem value="spam">Spam Email</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <label className="text-sm font-medium">Threshold Profile</label>
                <Select value={thresholdProfile} onValueChange={(value: any) => setThresholdProfile(value)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="strict">Strict (High Security)</SelectItem>
                    <SelectItem value="balanced">Balanced (Default)</SelectItem>
                    <SelectItem value="lenient">Lenient (Low False Positives)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-end space-x-2">
                <Button 
                  onClick={handleAnalyze} 
                  disabled={loading || !emailContent.trim()}
                  className="flex-1"
                >
                  {loading ? (
                    <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                  ) : (
                    <Play className="h-4 w-4 mr-2" />
                  )}
                  Analyze Email
                </Button>
                
                {data && (
                  <Button 
                    variant="outline" 
                    onClick={handleCompareAnalysis}
                    className="flex items-center space-x-1"
                  >
                    <Compare className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </div>

            {/* Email Content Input */}
            <div>
              <label className="text-sm font-medium">Email Content</label>
              <Textarea
                value={emailContent}
                onChange={(e) => setEmailContent(e.target.value)}
                placeholder="Paste email content here..."
                rows={8}
                className="mt-1"
              />
            </div>

            {/* Error Display */}
            {error && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>

        {/* Comparison Panel */}
        {(baseline || comparisons.length > 0) && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Compare className="h-5 w-5" />
                  <span>Analysis Comparison</span>
                </div>
                <Button variant="outline" size="sm" onClick={clearComparisons}>
                  Clear Comparisons
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {baseline && (
                  <div className="flex items-center space-x-2">
                    <Badge variant="outline">Baseline</Badge>
                    <span className="text-sm">
                      Score: {(baseline.threat_score * 100).toFixed(1)}% | 
                      Level: {baseline.threat_level} | 
                      Hash: {baseline.deterministic_hash.slice(-8)}
                    </span>
                  </div>
                )}
                
                {comparisons.map((comparison, index) => (
                  <div key={index} className="flex items-center space-x-2">
                    <Badge>Comparison {index + 1}</Badge>
                    <span className="text-sm">
                      Score: {(comparison.threat_score * 100).toFixed(1)}% | 
                      Level: {comparison.threat_level} | 
                      Hash: {comparison.deterministic_hash.slice(-8)}
                    </span>
                    {differences[index]?.hash_match && (
                      <Badge variant="success" className="text-xs">
                        <Check className="h-3 w-3 mr-1" />
                        Deterministic
                      </Badge>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Main Analysis Results */}
        {displayData && (
          <ThreatExplanationDashboard threatAnalysis={displayData} />
        )}

        {/* Testing Instructions */}
        <Card>
          <CardHeader>
            <CardTitle>Testing Instructions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2">Deterministic Testing</h4>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>• Run the same email multiple times</li>
                  <li>• Verify identical threat scores and hashes</li>
                  <li>• Compare different threshold profiles</li>
                  <li>• Test with various email samples</li>
                </ul>
              </div>
              
              <div>
                <h4 className="font-semibold mb-2">Explainability Features</h4>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>• Review component contribution breakdown</li>
                  <li>• Examine top contributing signals</li>
                  <li>• Check confidence bands and certainty factors</li>
                  <li>• Analyze reasoning and risk factors</li>
                </ul>
              </div>
            </div>
            
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                This interface demonstrates the deterministic threat scoring system. 
                The same email content should always produce identical threat scores and explanations 
                when analyzed with the same threshold profile.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}