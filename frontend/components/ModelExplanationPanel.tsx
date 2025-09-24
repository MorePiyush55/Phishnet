import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertTriangle, CheckCircle, XCircle, Info, Brain, Target, Shield, Eye } from 'lucide-react';

interface FeatureExplanation {
  feature_name: string;
  importance_score: number;
  contribution: number;
  explanation: string;
}

interface MLPredictionResponse {
  is_phishing: boolean;
  confidence: number;
  risk_score: number;
  content_model_score: number;
  url_model_score: number;
  sender_model_score: number;
  top_risk_factors: FeatureExplanation[];
  explanation_summary: string;
  model_confidence: 'high' | 'medium' | 'low';
  processing_time_ms: number;
  model_version: string;
  analysis_timestamp: string;
}

interface ModelExplanationPanelProps {
  prediction: MLPredictionResponse;
  onFeedback: (feedback: 'correct' | 'incorrect', reason: string) => void;
}

const ModelExplanationPanel: React.FC<ModelExplanationPanelProps> = ({ 
  prediction, 
  onFeedback 
}) => {
  const [showFeedbackModal, setShowFeedbackModal] = useState(false);
  const [feedbackType, setFeedbackType] = useState<'correct' | 'incorrect'>('correct');
  const [feedbackReason, setFeedbackReason] = useState('');

  const getRiskLevelColor = (riskScore: number) => {
    if (riskScore >= 0.8) return 'text-red-600 bg-red-50 border-red-200';
    if (riskScore >= 0.6) return 'text-orange-600 bg-orange-50 border-orange-200';
    if (riskScore >= 0.4) return 'text-yellow-600 bg-yellow-50 border-yellow-200';
    return 'text-green-600 bg-green-50 border-green-200';
  };

  const getConfidenceIcon = (confidence: string) => {
    switch (confidence) {
      case 'high': return <CheckCircle className=\"h-4 w-4 text-green-600\" />;
      case 'medium': return <AlertTriangle className=\"h-4 w-4 text-yellow-600\" />;
      case 'low': return <XCircle className=\"h-4 w-4 text-red-600\" />;
      default: return <Info className=\"h-4 w-4\" />;
    }
  };

  const handleFeedbackSubmit = () => {
    onFeedback(feedbackType, feedbackReason);
    setShowFeedbackModal(false);
    setFeedbackReason('');
  };

  return (
    <div className=\"space-y-6\">
      {/* Main Prediction Summary */}
      <Card className={`border-2 ${getRiskLevelColor(prediction.risk_score)}`}>
        <CardHeader className=\"pb-3\">
          <div className=\"flex items-center justify-between\">
            <div className=\"flex items-center space-x-3\">
              <div className=\"flex items-center space-x-2\">
                {prediction.is_phishing ? (
                  <Shield className=\"h-6 w-6 text-red-600\" />
                ) : (
                  <CheckCircle className=\"h-6 w-6 text-green-600\" />
                )}
                <CardTitle className=\"text-xl\">
                  {prediction.is_phishing ? 'PHISHING DETECTED' : 'EMAIL LEGITIMATE'}
                </CardTitle>
              </div>
              <Badge variant={prediction.is_phishing ? 'destructive' : 'success'}>
                {(prediction.confidence * 100).toFixed(1)}% confident
              </Badge>
            </div>
            
            <div className=\"flex items-center space-x-2\">
              {getConfidenceIcon(prediction.model_confidence)}
              <span className=\"text-sm text-gray-500 capitalize\">
                {prediction.model_confidence} confidence
              </span>
            </div>
          </div>
        </CardHeader>
        
        <CardContent>
          <div className=\"space-y-4\">
            {/* Risk Score Visualization */}
            <div>
              <div className=\"flex justify-between items-center mb-2\">
                <span className=\"text-sm font-medium\">Risk Score</span>
                <span className=\"text-sm font-mono\">{(prediction.risk_score * 100).toFixed(1)}%</span>
              </div>
              <Progress 
                value={prediction.risk_score * 100} 
                className=\"h-3\"
                indicatorClassName={`${
                  prediction.risk_score >= 0.8 ? 'bg-red-500' :
                  prediction.risk_score >= 0.6 ? 'bg-orange-500' :
                  prediction.risk_score >= 0.4 ? 'bg-yellow-500' : 'bg-green-500'
                }`}
              />
            </div>

            {/* Explanation Summary */}
            <div className=\"bg-gray-50 p-3 rounded-lg\">
              <div className=\"flex items-start space-x-2\">
                <Brain className=\"h-5 w-5 text-blue-600 mt-0.5 flex-shrink-0\" />
                <p className=\"text-sm text-gray-700\">{prediction.explanation_summary}</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Detailed Analysis Tabs */}
      <Tabs defaultValue=\"explanation\" className=\"w-full\">
        <TabsList className=\"grid w-full grid-cols-4\">
          <TabsTrigger value=\"explanation\" className=\"flex items-center space-x-1\">
            <Eye className=\"h-4 w-4\" />
            <span>Why</span>
          </TabsTrigger>
          <TabsTrigger value=\"models\" className=\"flex items-center space-x-1\">
            <Target className=\"h-4 w-4\" />
            <span>Models</span>
          </TabsTrigger>
          <TabsTrigger value=\"features\" className=\"flex items-center space-x-1\">
            <Brain className=\"h-4 w-4\" />
            <span>Features</span>
          </TabsTrigger>
          <TabsTrigger value=\"technical\" className=\"flex items-center space-x-1\">
            <Info className=\"h-4 w-4\" />
            <span>Technical</span>
          </TabsTrigger>
        </TabsList>

        {/* Why Panel - Top 5 Features */}
        <TabsContent value=\"explanation\">
          <Card>
            <CardHeader>
              <CardTitle className=\"flex items-center space-x-2\">
                <Eye className=\"h-5 w-5\" />
                <span>Top Risk Factors</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className=\"space-y-4\">
                {prediction.top_risk_factors.map((factor, index) => (
                  <div key={index} className=\"border rounded-lg p-4\">
                    <div className=\"flex items-center justify-between mb-2\">
                      <h4 className=\"font-medium text-gray-900\">{factor.feature_name}</h4>
                      <div className=\"flex items-center space-x-2\">
                        <Badge variant={factor.contribution > 0 ? 'destructive' : 'success'}>
                          {factor.contribution > 0 ? '+' : ''}{(factor.contribution * 100).toFixed(1)}%
                        </Badge>
                      </div>
                    </div>
                    
                    <Progress 
                      value={Math.abs(factor.importance_score) * 100} 
                      className=\"h-2 mb-2\"
                      indicatorClassName={factor.contribution > 0 ? 'bg-red-500' : 'bg-green-500'}
                    />
                    
                    <p className=\"text-sm text-gray-600\">{factor.explanation}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Individual Model Scores */}
        <TabsContent value=\"models\">
          <Card>
            <CardHeader>
              <CardTitle className=\"flex items-center space-x-2\">
                <Target className=\"h-5 w-5\" />
                <span>Individual Model Contributions</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className=\"space-y-4\">
                <div className=\"grid grid-cols-1 md:grid-cols-3 gap-4\">
                  {/* Content Model */}
                  <div className=\"border rounded-lg p-4\">
                    <div className=\"flex items-center space-x-2 mb-3\">
                      <div className=\"w-3 h-3 bg-blue-500 rounded-full\"></div>
                      <h4 className=\"font-medium\">Content Analysis</h4>
                    </div>
                    <div className=\"text-2xl font-bold text-gray-900\">
                      {(prediction.content_model_score * 100).toFixed(1)}%
                    </div>
                    <Progress 
                      value={prediction.content_model_score * 100} 
                      className=\"h-2 mt-2\"
                      indicatorClassName=\"bg-blue-500\"
                    />
                    <p className=\"text-xs text-gray-500 mt-2\">
                      Analyzes email text, language patterns, and suspicious content
                    </p>
                  </div>

                  {/* URL Model */}
                  <div className=\"border rounded-lg p-4\">
                    <div className=\"flex items-center space-x-2 mb-3\">
                      <div className=\"w-3 h-3 bg-purple-500 rounded-full\"></div>
                      <h4 className=\"font-medium\">URL Analysis</h4>
                    </div>
                    <div className=\"text-2xl font-bold text-gray-900\">
                      {(prediction.url_model_score * 100).toFixed(1)}%
                    </div>
                    <Progress 
                      value={prediction.url_model_score * 100} 
                      className=\"h-2 mt-2\"
                      indicatorClassName=\"bg-purple-500\"
                    />
                    <p className=\"text-xs text-gray-500 mt-2\">
                      Examines links, domain reputation, and URL characteristics
                    </p>
                  </div>

                  {/* Sender Model */}
                  <div className=\"border rounded-lg p-4\">
                    <div className=\"flex items-center space-x-2 mb-3\">
                      <div className=\"w-3 h-3 bg-green-500 rounded-full\"></div>
                      <h4 className=\"font-medium\">Sender Behavior</h4>
                    </div>
                    <div className=\"text-2xl font-bold text-gray-900\">
                      {(prediction.sender_model_score * 100).toFixed(1)}%
                    </div>
                    <Progress 
                      value={prediction.sender_model_score * 100} 
                      className=\"h-2 mt-2\"
                      indicatorClassName=\"bg-green-500\"
                    />
                    <p className=\"text-xs text-gray-500 mt-2\">
                      Evaluates sender history, reputation, and behavioral patterns
                    </p>
                  </div>
                </div>

                {/* Model Weights */}
                <div className=\"bg-gray-50 p-4 rounded-lg\">
                  <h4 className=\"font-medium mb-3 text-gray-900\">Ensemble Weighting</h4>
                  <div className=\"space-y-2\">
                    <div className=\"flex justify-between items-center\">
                      <span className=\"text-sm\">Content Model</span>
                      <span className=\"text-sm font-medium\">40%</span>
                    </div>
                    <div className=\"flex justify-between items-center\">
                      <span className=\"text-sm\">URL Model</span>
                      <span className=\"text-sm font-medium\">35%</span>
                    </div>
                    <div className=\"flex justify-between items-center\">
                      <span className=\"text-sm\">Sender Model</span>
                      <span className=\"text-sm font-medium\">25%</span>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Feature Details */}
        <TabsContent value=\"features\">
          <Card>
            <CardHeader>
              <CardTitle className=\"flex items-center space-x-2\">
                <Brain className=\"h-5 w-5\" />
                <span>Feature Analysis</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className=\"space-y-6\">
                {/* Feature Categories */}
                <div className=\"grid grid-cols-1 md:grid-cols-2 gap-6\">
                  <div>
                    <h4 className=\"font-medium text-gray-900 mb-3\">Content Features</h4>
                    <ul className=\"space-y-2 text-sm text-gray-600\">
                      <li>• Suspicious keyword detection</li>
                      <li>• Urgency and pressure indicators</li>
                      <li>• Grammar and spelling analysis</li>
                      <li>• Social engineering patterns</li>
                    </ul>
                  </div>
                  
                  <div>
                    <h4 className=\"font-medium text-gray-900 mb-3\">URL Features</h4>
                    <ul className=\"space-y-2 text-sm text-gray-600\">
                      <li>• Domain reputation scoring</li>
                      <li>• URL shortener detection</li>
                      <li>• Typosquatting analysis</li>
                      <li>• Malicious TLD detection</li>
                    </ul>
                  </div>
                  
                  <div>
                    <h4 className=\"font-medium text-gray-900 mb-3\">Sender Features</h4>
                    <ul className=\"space-y-2 text-sm text-gray-600\">
                      <li>• Historical reputation</li>
                      <li>• Authentication validation</li>
                      <li>• Behavioral pattern analysis</li>
                      <li>• Geographic anomalies</li>
                    </ul>
                  </div>
                  
                  <div>
                    <h4 className=\"font-medium text-gray-900 mb-3\">Technical Features</h4>
                    <ul className=\"space-y-2 text-sm text-gray-600\">
                      <li>• Header analysis</li>
                      <li>• Encoding anomalies</li>
                      <li>• Attachment scanning</li>
                      <li>• Network indicators</li>
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Technical Details */}
        <TabsContent value=\"technical\">
          <Card>
            <CardHeader>
              <CardTitle className=\"flex items-center space-x-2\">
                <Info className=\"h-5 w-5\" />
                <span>Technical Information</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className=\"grid grid-cols-1 md:grid-cols-2 gap-6\">
                <div>
                  <h4 className=\"font-medium text-gray-900 mb-3\">Model Information</h4>
                  <div className=\"space-y-2 text-sm\">
                    <div className=\"flex justify-between\">
                      <span className=\"text-gray-600\">Model Version:</span>
                      <span className=\"font-mono\">{prediction.model_version}</span>
                    </div>
                    <div className=\"flex justify-between\">
                      <span className=\"text-gray-600\">Processing Time:</span>
                      <span className=\"font-mono\">{prediction.processing_time_ms.toFixed(1)}ms</span>
                    </div>
                    <div className=\"flex justify-between\">
                      <span className=\"text-gray-600\">Analysis Time:</span>
                      <span className=\"font-mono\">
                        {new Date(prediction.analysis_timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h4 className=\"font-medium text-gray-900 mb-3\">Model Architecture</h4>
                  <div className=\"space-y-2 text-sm text-gray-600\">
                    <div>• Transformer-based content analysis</div>
                    <div>• Random Forest URL classifier</div>
                    <div>• Gradient Boosting sender model</div>
                    <div>• LIME/SHAP explainability</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Feedback Section */}
      <Card className=\"border-blue-200 bg-blue-50\">
        <CardContent className=\"pt-6\">
          <div className=\"flex items-center justify-between\">
            <div>
              <h4 className=\"font-medium text-blue-900 mb-1\">Help Improve Our Model</h4>
              <p className=\"text-sm text-blue-700\">
                Was this analysis correct? Your feedback helps improve detection accuracy.
              </p>
            </div>
            <div className=\"space-x-2\">
              <Button 
                variant=\"outline\" 
                size=\"sm\"
                onClick={() => {
                  setFeedbackType('correct');
                  setShowFeedbackModal(true);
                }}
                className=\"border-green-300 text-green-700 hover:bg-green-50\"
              >
                <CheckCircle className=\"h-4 w-4 mr-1\" />
                Correct
              </Button>
              <Button 
                variant=\"outline\" 
                size=\"sm\"
                onClick={() => {
                  setFeedbackType('incorrect');
                  setShowFeedbackModal(true);
                }}
                className=\"border-red-300 text-red-700 hover:bg-red-50\"
              >
                <XCircle className=\"h-4 w-4 mr-1\" />
                Incorrect
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Feedback Modal */}
      {showFeedbackModal && (
        <div className=\"fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50\">
          <div className=\"bg-white rounded-lg p-6 w-96 max-w-full mx-4\">
            <h3 className=\"text-lg font-semibold mb-4\">
              Feedback on Analysis
            </h3>
            
            <div className=\"mb-4\">
              <label className=\"block text-sm font-medium text-gray-700 mb-2\">
                Why do you think this analysis is {feedbackType}?
              </label>
              <textarea
                value={feedbackReason}
                onChange={(e) => setFeedbackReason(e.target.value)}
                className=\"w-full h-24 p-3 border border-gray-300 rounded-md resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent\"
                placeholder=\"Please provide details to help improve our model...\"
              />
            </div>
            
            <div className=\"flex space-x-3 justify-end\">
              <Button
                variant=\"outline\"
                onClick={() => setShowFeedbackModal(false)}
              >
                Cancel
              </Button>
              <Button
                onClick={handleFeedbackSubmit}
                disabled={!feedbackReason.trim()}
                className={feedbackType === 'correct' ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700'}
              >
                Submit Feedback
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ModelExplanationPanel;