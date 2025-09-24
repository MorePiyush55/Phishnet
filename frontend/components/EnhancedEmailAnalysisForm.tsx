import React, { useState, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Mail, 
  Send, 
  Link, 
  User, 
  Clock, 
  Shield, 
  Loader2, 
  Upload,
  AlertTriangle,
  Brain,
  Zap
} from 'lucide-react';
import ModelExplanationPanel from './ModelExplanationPanel';

interface EmailAnalysisRequest {
  sender: string;
  subject: string;
  content: string;
  urls?: string[];
  headers?: Record<string, any>;
  sender_history?: Record<string, any>;
}

interface MLPredictionResponse {
  is_phishing: boolean;
  confidence: number;
  risk_score: number;
  content_model_score: number;
  url_model_score: number;
  sender_model_score: number;
  top_risk_factors: Array<{
    feature_name: string;
    importance_score: number;
    contribution: number;
    explanation: string;
  }>;
  explanation_summary: string;
  model_confidence: 'high' | 'medium' | 'low';
  processing_time_ms: number;
  model_version: string;
  analysis_timestamp: string;
}

const EnhancedEmailAnalysisForm: React.FC = () => {
  const [formData, setFormData] = useState<EmailAnalysisRequest>({
    sender: '',
    subject: '',
    content: '',
    urls: [],
    headers: {},
    sender_history: {}
  });

  const [prediction, setPrediction] = useState<MLPredictionResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysisMode, setAnalysisMode] = useState<'basic' | 'advanced'>('basic');
  const [rawEmailText, setRawEmailText] = useState('');

  // Parse raw email text into structured data
  const parseRawEmail = useCallback((rawText: string) => {
    const lines = rawText.split('\\n');
    let sender = '';
    let subject = '';
    let content = '';
    let inHeaders = true;
    
    const urls: string[] = [];
    const headers: Record<string, string> = {};

    for (const line of lines) {
      if (inHeaders) {
        if (line.trim() === '') {
          inHeaders = false;
          continue;
        }
        
        // Parse headers
        const headerMatch = line.match(/^([^:]+):\\s*(.+)$/);
        if (headerMatch) {
          const [, key, value] = headerMatch;
          headers[key.toLowerCase()] = value;
          
          if (key.toLowerCase() === 'from') {
            sender = value;
          } else if (key.toLowerCase() === 'subject') {
            subject = value;
          }
        }
      } else {
        content += line + '\n';
      }
    }

    // Extract URLs from content
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const foundUrls = content.match(urlRegex) || [];
    urls.push(...foundUrls);

    setFormData({
      sender,
      subject,
      content: content.trim(),
      urls,
      headers,
      sender_history: {}
    });
  }, []);

  const handleRawEmailChange = (value: string) => {
    setRawEmailText(value);
    if (value.trim()) {
      parseRawEmail(value);
    }
  };

  const handleFieldChange = (field: keyof EmailAnalysisRequest, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleAnalyze = async () => {
    if (!formData.sender || !formData.subject || !formData.content) {
      setError('Please fill in all required fields');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setPrediction(null);

    try {
      const response = await fetch('/api/v1/ml/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}` // Adjust as needed
        },
        body: JSON.stringify(formData)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Analysis failed');
      }

      const result: MLPredictionResponse = await response.json();
      setPrediction(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during analysis');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFeedback = async (feedback: 'correct' | 'incorrect', reason: string) => {
    if (!prediction) return;

    try {
      await fetch('/api/v1/ml/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          original_prediction: prediction.confidence,
          correct_label: feedback === 'correct' ? (prediction.is_phishing ? 1 : 0) : (prediction.is_phishing ? 0 : 1),
          feedback_reason: reason,
          confidence_in_correction: 0.9,
          email_data: formData
        })
      });

      // Show success message (you could add a toast here)
      console.log('Feedback submitted successfully');
    } catch (err) {
      console.error('Failed to submit feedback:', err);
    }
  };

  const addUrl = () => {
    setFormData(prev => ({
      ...prev,
      urls: [...(prev.urls || []), '']
    }));
  };

  const updateUrl = (index: number, value: string) => {
    setFormData(prev => ({
      ...prev,
      urls: prev.urls?.map((url, i) => i === index ? value : url) || []
    }));
  };

  const removeUrl = (index: number) => {
    setFormData(prev => ({
      ...prev,
      urls: prev.urls?.filter((_, i) => i !== index) || []
    }));
  };

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2 flex items-center justify-center space-x-3">
          <Brain className="h-8 w-8 text-blue-600" />
          <span>Advanced Email Analysis</span>
        </h1>
        <p className="text-gray-600 max-w-2xl mx-auto">
          Powered by AI ensemble models with explainable predictions and continuous learning
        </p>
      </div>

      <div className=\"grid grid-cols-1 lg:grid-cols-2 gap-6\">
        {/* Input Form */}
        <div className=\"space-y-6\">
          <Card>
            <CardHeader>
              <div className=\"flex items-center justify-between\">
                <CardTitle className=\"flex items-center space-x-2\">
                  <Mail className=\"h-5 w-5\" />
                  <span>Email Analysis</span>
                </CardTitle>
                <div className=\"flex space-x-2\">
                  <Button
                    variant={analysisMode === 'basic' ? 'default' : 'outline'}
                    size=\"sm\"
                    onClick={() => setAnalysisMode('basic')}
                  >
                    Basic
                  </Button>
                  <Button
                    variant={analysisMode === 'advanced' ? 'default' : 'outline'}
                    size=\"sm\"
                    onClick={() => setAnalysisMode('advanced')}
                  >
                    Advanced
                  </Button>
                </div>
              </div>
            </CardHeader>

            <CardContent>
              <Tabs value={analysisMode} onValueChange={(value) => setAnalysisMode(value as 'basic' | 'advanced')}>
                <TabsList className=\"grid w-full grid-cols-2\">
                  <TabsTrigger value=\"basic\">Form Input</TabsTrigger>
                  <TabsTrigger value=\"advanced\">Raw Email</TabsTrigger>
                </TabsList>

                {/* Basic Form Input */}
                <TabsContent value=\"basic\" className=\"space-y-4 mt-4\">
                  <div className=\"space-y-4\">
                    <div>
                      <Label htmlFor=\"sender\" className=\"flex items-center space-x-1\">
                        <User className=\"h-4 w-4\" />
                        <span>Sender Email *</span>
                      </Label>
                      <Input
                        id=\"sender\"
                        type=\"email\"
                        placeholder=\"suspicious@example.com\"
                        value={formData.sender}
                        onChange={(e) => handleFieldChange('sender', e.target.value)}
                        className=\"mt-1\"
                      />
                    </div>

                    <div>
                      <Label htmlFor=\"subject\" className=\"flex items-center space-x-1\">
                        <Send className=\"h-4 w-4\" />
                        <span>Subject *</span>
                      </Label>
                      <Input
                        id=\"subject\"
                        placeholder=\"Urgent: Verify your account immediately\"
                        value={formData.subject}
                        onChange={(e) => handleFieldChange('subject', e.target.value)}
                        className=\"mt-1\"
                      />
                    </div>

                    <div>
                      <Label htmlFor=\"content\" className=\"flex items-center space-x-1\">
                        <Mail className=\"h-4 w-4\" />
                        <span>Email Content *</span>
                      </Label>
                      <Textarea
                        id=\"content\"
                        placeholder=\"Dear customer, your account has been suspended...\"
                        value={formData.content}
                        onChange={(e) => handleFieldChange('content', e.target.value)}
                        className=\"mt-1 h-32\"
                      />
                    </div>

                    {/* URLs Section */}
                    <div>
                      <div className=\"flex items-center justify-between mb-2\">
                        <Label className=\"flex items-center space-x-1\">
                          <Link className=\"h-4 w-4\" />
                          <span>URLs in Email</span>
                        </Label>
                        <Button
                          type=\"button\"
                          variant=\"outline\"
                          size=\"sm\"
                          onClick={addUrl}
                        >
                          Add URL
                        </Button>
                      </div>
                      <div className=\"space-y-2\">
                        {formData.urls?.map((url, index) => (
                          <div key={index} className=\"flex space-x-2\">
                            <Input
                              placeholder=\"https://suspicious-site.com\"
                              value={url}
                              onChange={(e) => updateUrl(index, e.target.value)}
                            />
                            <Button
                              type=\"button\"
                              variant=\"outline\"
                              size=\"sm\"
                              onClick={() => removeUrl(index)}
                            >
                              Remove
                            </Button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </TabsContent>

                {/* Raw Email Input */}
                <TabsContent value=\"advanced\" className=\"mt-4\">
                  <div>
                    <Label htmlFor=\"raw-email\" className=\"flex items-center space-x-1 mb-2\">
                      <Upload className=\"h-4 w-4\" />
                      <span>Raw Email Text</span>
                    </Label>
                    <Textarea
                      id=\"raw-email\"
                      placeholder={`From: suspicious@example.com
Subject: Urgent: Verify your account
Date: Mon, 1 Jan 2024 10:00:00 +0000

Dear customer,
Your account has been suspended due to suspicious activity...`}
                      value={rawEmailText}
                      onChange={(e) => handleRawEmailChange(e.target.value)}
                      className=\"h-48 font-mono text-sm\"
                    />
                    <p className=\"text-xs text-gray-500 mt-1\">
                      Paste the complete email including headers. Fields will be auto-populated.
                    </p>
                  </div>
                </TabsContent>
              </Tabs>

              {/* Error Display */}
              {error && (
                <Alert variant=\"destructive\" className=\"mt-4\">
                  <AlertTriangle className=\"h-4 w-4\" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              {/* Analyze Button */}
              <Button
                onClick={handleAnalyze}
                disabled={isAnalyzing || !formData.sender || !formData.subject || !formData.content}
                className=\"w-full mt-4 h-12\"
                size=\"lg\"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className=\"mr-2 h-5 w-5 animate-spin\" />
                    Analyzing with AI Ensemble...
                  </>
                ) : (
                  <>
                    <Zap className=\"mr-2 h-5 w-5\" />
                    Analyze Email
                  </>
                )}
              </Button>

              {/* Quick Stats */}
              {formData.content && !isAnalyzing && (
                <div className=\"mt-4 p-3 bg-gray-50 rounded-lg\">
                  <div className=\"grid grid-cols-2 gap-4 text-sm\">
                    <div>
                      <span className=\"text-gray-600\">Content Length:</span>
                      <span className=\"ml-2 font-medium\">{formData.content.length} chars</span>
                    </div>
                    <div>
                      <span className=\"text-gray-600\">URLs Found:</span>
                      <span className=\"ml-2 font-medium\">{formData.urls?.length || 0}</span>
                    </div>
                    <div>
                      <span className=\"text-gray-600\">Word Count:</span>
                      <span className=\"ml-2 font-medium\">{formData.content.split(/\\s+/).length}</span>
                    </div>
                    <div>
                      <span className=\"text-gray-600\">Analysis Ready:</span>
                      <Badge variant={formData.sender && formData.subject && formData.content ? 'success' : 'secondary'} className=\"ml-2\">
                        {formData.sender && formData.subject && formData.content ? 'Yes' : 'No'}
                      </Badge>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Results Panel */}
        <div>
          {isAnalyzing && (
            <Card>
              <CardContent className=\"pt-6\">
                <div className=\"flex flex-col items-center justify-center py-12 space-y-4\">
                  <Loader2 className=\"h-12 w-12 animate-spin text-blue-600\" />
                  <div className=\"text-center\">
                    <h3 className=\"text-lg font-medium text-gray-900\">Analyzing Email</h3>
                    <p className=\"text-sm text-gray-500 mt-2\">
                      Running advanced AI models for comprehensive threat detection...
                    </p>
                    <div className=\"mt-4 space-y-2 text-xs text-gray-400\">
                      <div className=\"flex items-center justify-center space-x-2\">
                        <div className=\"w-2 h-2 bg-blue-500 rounded-full animate-pulse\"></div>
                        <span>Content analysis with transformer model</span>
                      </div>
                      <div className=\"flex items-center justify-center space-x-2\">
                        <div className=\"w-2 h-2 bg-purple-500 rounded-full animate-pulse\" style={{animationDelay: '0.5s'}}></div>
                        <span>URL reputation and feature extraction</span>
                      </div>
                      <div className=\"flex items-center justify-center space-x-2\">
                        <div className=\"w-2 h-2 bg-green-500 rounded-full animate-pulse\" style={{animationDelay: '1s'}}></div>
                        <span>Sender behavior pattern analysis</span>
                      </div>
                      <div className=\"flex items-center justify-center space-x-2\">
                        <div className=\"w-2 h-2 bg-orange-500 rounded-full animate-pulse\" style={{animationDelay: '1.5s'}}></div>
                        <span>Ensemble prediction with explanations</span>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {prediction && !isAnalyzing && (
            <ModelExplanationPanel 
              prediction={prediction} 
              onFeedback={handleFeedback}
            />
          )}

          {!prediction && !isAnalyzing && (
            <Card className=\"border-dashed border-2 border-gray-200\">
              <CardContent className=\"pt-6\">
                <div className=\"flex flex-col items-center justify-center py-12 space-y-4 text-gray-400\">
                  <Brain className=\"h-16 w-16\" />
                  <div className=\"text-center\">
                    <h3 className=\"text-lg font-medium\">Ready for Analysis</h3>
                    <p className=\"text-sm mt-2\">
                      Enter email details and click analyze to get AI-powered threat assessment with explanations
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Feature Information */}
      <Card className=\"bg-blue-50 border-blue-200\">
        <CardContent className=\"pt-6\">
          <div className=\"text-center\">
            <h3 className=\"text-lg font-medium text-blue-900 mb-4\">Advanced AI Capabilities</h3>
            <div className=\"grid grid-cols-1 md:grid-cols-3 gap-6\">
              <div className=\"flex flex-col items-center space-y-2\">
                <div className=\"w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center\">
                  <Brain className=\"h-6 w-6 text-blue-600\" />
                </div>
                <h4 className=\"font-medium text-blue-900\">Transformer Models</h4>
                <p className=\"text-sm text-blue-700 text-center\">
                  BERT-based content analysis for sophisticated language understanding
                </p>
              </div>
              
              <div className=\"flex flex-col items-center space-y-2\">
                <div className=\"w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center\">
                  <Shield className=\"h-6 w-6 text-purple-600\" />
                </div>
                <h4 className=\"font-medium text-purple-900\">Adversarial Hardening</h4>
                <p className=\"text-sm text-purple-700 text-center\">
                  Robust against evasion attempts and sophisticated attack techniques
                </p>
              </div>
              
              <div className=\"flex flex-col items-center space-y-2\">
                <div className=\"w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center\">
                  <Zap className=\"h-6 w-6 text-green-600\" />
                </div>
                <h4 className=\"font-medium text-green-900\">Explainable AI</h4>
                <p className=\"text-sm text-green-700 text-center\">
                  LIME/SHAP integration provides clear reasoning for every prediction
                </p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default EnhancedEmailAnalysisForm;