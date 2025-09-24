import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock, Database, Wifi, Eye, Lock } from 'lucide-react';
import { ResultSourceIndicator } from './ThreatIntelligenceDashboard';

interface ThreatAnalysisResult {
  resource: string;
  resource_type: string;
  aggregated_score: number;
  confidence: number;
  sources_used: string[];
  cache_hit: boolean;
  privacy_protected: boolean;
  processing_time: number;
  errors: string[];
  threat_level: string;
  analysis_timestamp: string;
}

interface AnalysisRequestProps {
  onAnalysisComplete?: (result: ThreatAnalysisResult) => void;
}

const ThreatLevelBadge: React.FC<{ level: string; score: number }> = ({ level, score }) => {
  const getLevelColor = () => {
    switch (level.toLowerCase()) {
      case 'safe': return 'bg-green-100 text-green-800 border-green-200';
      case 'low': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'medium': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'high': return 'bg-red-100 text-red-800 border-red-200';
      case 'critical': return 'bg-red-200 text-red-900 border-red-300';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getLevelIcon = () => {
    switch (level.toLowerCase()) {
      case 'safe': return <CheckCircle className="w-4 h-4" />;
      case 'low': 
      case 'medium': return <AlertTriangle className="w-4 h-4" />;
      case 'high':
      case 'critical': return <Shield className="w-4 h-4" />;
      default: return <Eye className="w-4 h-4" />;
    }
  };

  return (
    <div className={`inline-flex items-center space-x-1 px-3 py-1 rounded-full border text-sm font-medium ${getLevelColor()}`}>
      {getLevelIcon()}
      <span className="capitalize">{level}</span>
      <span className="text-xs opacity-75">({(score * 100).toFixed(0)}%)</span>
    </div>
  );
};

const ThreatAnalysisForm: React.FC<AnalysisRequestProps> = ({ onAnalysisComplete }) => {
  const [analysisType, setAnalysisType] = useState<'url' | 'ip' | 'content'>('url');
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ThreatAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const endpoint = `/api/threat-intelligence/analyze/${analysisType}`;
      const body = analysisType === 'content' 
        ? { content: inputValue }
        : analysisType === 'ip'
          ? { ip_address: inputValue }
          : { url: inputValue };

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(body)
      });

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.statusText}`);
      }

      const analysisResult = await response.json();
      setResult(analysisResult);
      onAnalysisComplete?.(analysisResult);

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const getPlaceholder = () => {
    switch (analysisType) {
      case 'url': return 'https://suspicious-site.com';
      case 'ip': return '185.220.101.182';
      case 'content': return 'Urgent! Your account will be suspended. Click here to verify...';
      default: return '';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold mb-4">Threat Intelligence Analysis</h2>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Analysis Type Selection */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Analysis Type
          </label>
          <div className="flex space-x-4">
            {[
              { value: 'url', label: 'URL Analysis', icon: <Wifi className="w-4 h-4" /> },
              { value: 'ip', label: 'IP Analysis', icon: <Shield className="w-4 h-4" /> },
              { value: 'content', label: 'Content Analysis', icon: <Eye className="w-4 h-4" /> }
            ].map((type) => (
              <label key={type.value} className="flex items-center">
                <input
                  type="radio"
                  value={type.value}
                  checked={analysisType === type.value}
                  onChange={(e) => setAnalysisType(e.target.value as any)}
                  className="mr-2"
                />
                <div className="flex items-center space-x-1">
                  {type.icon}
                  <span>{type.label}</span>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Input Field */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            {analysisType === 'content' ? 'Content to Analyze' : `${analysisType.toUpperCase()} to Analyze`}
          </label>
          {analysisType === 'content' ? (
            <textarea
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder={getPlaceholder()}
              rows={4}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          ) : (
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder={getPlaceholder()}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          )}
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={loading || !inputValue.trim()}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
        >
          {loading ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              <span>Analyzing...</span>
            </>
          ) : (
            <>
              <Shield className="w-4 h-4" />
              <span>Analyze Threat</span>
            </>
          )}
        </button>
      </form>

      {/* Error Display */}
      {error && (
        <div className="mt-4 bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="w-5 h-5 text-red-500 mr-2" />
            <span className="text-red-800">{error}</span>
          </div>
        </div>
      )}

      {/* Results Display */}
      {result && (
        <div className="mt-6 space-y-4">
          <div className="border-t pt-4">
            <h3 className="text-lg font-semibold mb-3">Analysis Results</h3>
            
            {/* Main Result */}
            <div className="bg-gray-50 rounded-lg p-4 mb-4">
              <div className="flex items-center justify-between mb-3">
                <ThreatLevelBadge level={result.threat_level} score={result.aggregated_score} />
                <div className="text-sm text-gray-600">
                  Confidence: {(result.confidence * 100).toFixed(1)}%
                </div>
              </div>
              
              <div className="text-sm text-gray-700 mb-2">
                <strong>Resource:</strong> {result.resource}
              </div>
              <div className="text-sm text-gray-700">
                <strong>Type:</strong> {result.resource_type.replace('_', ' ').toUpperCase()}
              </div>
            </div>

            {/* Source and Cache Information */}
            <ResultSourceIndicator result={result} />

            {/* Privacy Protection Indicator */}
            {result.privacy_protected && (
              <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                <div className="flex items-center space-x-2">
                  <Lock className="w-4 h-4 text-green-600" />
                  <span className="text-green-800 font-medium">Privacy Protected</span>
                  <span className="text-green-700 text-sm">
                    Sensitive data was sanitized before external API calls
                  </span>
                </div>
              </div>
            )}

            {/* Detailed Information */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
              <div className="bg-white border rounded-lg p-3">
                <div className="flex items-center space-x-2 mb-2">
                  <Clock className="w-4 h-4 text-blue-500" />
                  <span className="font-medium">Processing Time</span>
                </div>
                <div className="text-lg font-bold text-blue-600">
                  {(result.processing_time * 1000).toFixed(0)}ms
                </div>
              </div>

              <div className="bg-white border rounded-lg p-3">
                <div className="flex items-center space-x-2 mb-2">
                  <Database className="w-4 h-4 text-green-500" />
                  <span className="font-medium">Data Source</span>
                </div>
                <div className="text-lg font-bold text-green-600">
                  {result.cache_hit ? 'Cache' : 'Live API'}
                </div>
              </div>

              <div className="bg-white border rounded-lg p-3">
                <div className="flex items-center space-x-2 mb-2">
                  <Shield className="w-4 h-4 text-purple-500" />
                  <span className="font-medium">Sources Used</span>
                </div>
                <div className="text-lg font-bold text-purple-600">
                  {result.sources_used.length}
                </div>
              </div>
            </div>

            {/* Errors (if any) */}
            {result.errors.length > 0 && (
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
                <div className="flex items-center space-x-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-600" />
                  <span className="font-medium text-yellow-800">Warnings</span>
                </div>
                <ul className="text-sm text-yellow-700 space-y-1">
                  {result.errors.map((error, index) => (
                    <li key={index}>• {error}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Timestamp */}
            <div className="text-xs text-gray-500 text-center">
              Analysis completed at {new Date(result.analysis_timestamp).toLocaleString()}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatAnalysisForm;
export { ThreatLevelBadge };