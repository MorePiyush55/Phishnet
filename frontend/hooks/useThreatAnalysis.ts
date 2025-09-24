import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/context/AuthContext';

export interface ThreatAnalysisResponse {
  threat_score: number;
  threat_level: string;
  recommended_action: string;
  deterministic_hash: string;
  explanation: {
    reasoning: string;
    confidence_band: {
      lower_bound: number;
      upper_bound: number;
      confidence_level: number;
    };
    top_signals: Array<{
      name: string;
      description: string;
      component: string;
      contribution: number;
      evidence: string[];
      rank?: number;
    }>;
    component_breakdown: Record<string, number>;
    certainty_factors: Record<string, number>;
    risk_factors: string[];
  };
  components: Array<{
    type: string;
    score: number;
    confidence: number;
    signals: string[];
    processing_time: number;
  }>;
  metadata: {
    threshold_profile: string;
    processing_time: number;
    timestamp: string;
    version: string;
  };
}

export interface ThreatAnalysisHistoryResponse {
  session_id: string;
  email_content: string;
  content_hash: string;
  analysis_result: ThreatAnalysisResponse;
  created_at: string;
  updated_at: string;
}

interface UseAnalysisState {
  data: ThreatAnalysisResponse | null;
  history: ThreatAnalysisHistoryResponse[];
  loading: boolean;
  error: string | null;
}

interface UseAnalysisResult extends UseAnalysisState {
  analyzeEmail: (emailContent: string, options?: AnalysisOptions) => Promise<void>;
  getAnalysisHistory: (contentHash?: string) => Promise<void>;
  verifyDeterministic: (contentHash: string) => Promise<boolean>;
  clearError: () => void;
  clearData: () => void;
}

interface AnalysisOptions {
  threshold_profile?: 'strict' | 'balanced' | 'lenient';
  force_reanalysis?: boolean;
  include_explanation?: boolean;
}

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const useThreatAnalysis = (): UseAnalysisResult => {
  const { token } = useAuth();
  const [state, setState] = useState<UseAnalysisState>({
    data: null,
    history: [],
    loading: false,
    error: null,
  });

  const setLoading = (loading: boolean) => {
    setState(prev => ({ ...prev, loading }));
  };

  const setError = (error: string | null) => {
    setState(prev => ({ ...prev, error, loading: false }));
  };

  const setData = (data: ThreatAnalysisResponse | null) => {
    setState(prev => ({ ...prev, data, loading: false, error: null }));
  };

  const setHistory = (history: ThreatAnalysisHistoryResponse[]) => {
    setState(prev => ({ ...prev, history }));
  };

  const makeAuthenticatedRequest = async (
    url: string, 
    options: RequestInit = {}
  ): Promise<Response> => {
    const headers = {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
      ...options.headers,
    };

    const response = await fetch(`${API_BASE_URL}${url}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
    }

    return response;
  };

  const analyzeEmail = useCallback(async (
    emailContent: string, 
    options: AnalysisOptions = {}
  ): Promise<void> => {
    if (!emailContent.trim()) {
      setError('Email content cannot be empty');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const requestBody = {
        email_content: emailContent,
        threshold_profile: options.threshold_profile || 'balanced',
        force_reanalysis: options.force_reanalysis || false,
        include_explanation: options.include_explanation !== false, // Default to true
      };

      const response = await makeAuthenticatedRequest('/api/v1/threat/analyze', {
        method: 'POST',
        body: JSON.stringify(requestBody),
      });

      const result: ThreatAnalysisResponse = await response.json();
      setData(result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to analyze email';
      setError(errorMessage);
      console.error('Analysis error:', error);
    }
  }, [token]);

  const getAnalysisHistory = useCallback(async (contentHash?: string): Promise<void> => {
    setLoading(true);
    
    try {
      const queryParams = contentHash ? `?content_hash=${encodeURIComponent(contentHash)}` : '';
      const response = await makeAuthenticatedRequest(`/api/v1/threat/history${queryParams}`);
      
      const result: ThreatAnalysisHistoryResponse[] = await response.json();
      setHistory(result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch analysis history';
      setError(errorMessage);
      console.error('History fetch error:', error);
    } finally {
      setLoading(false);
    }
  }, [token]);

  const verifyDeterministic = useCallback(async (contentHash: string): Promise<boolean> => {
    try {
      const response = await makeAuthenticatedRequest(`/api/v1/threat/verify-deterministic/${encodeURIComponent(contentHash)}`);
      const result = await response.json();
      return result.is_deterministic;
    } catch (error) {
      console.error('Deterministic verification error:', error);
      return false;
    }
  }, [token]);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const clearData = useCallback(() => {
    setState({
      data: null,
      history: [],
      loading: false,
      error: null,
    });
  }, []);

  return {
    ...state,
    analyzeEmail,
    getAnalysisHistory,
    verifyDeterministic,
    clearError,
    clearData,
  };
};

// Hook for real-time analysis updates
export const useRealTimeAnalysis = () => {
  const [isConnected, setIsConnected] = useState(false);
  const [analysisUpdates, setAnalysisUpdates] = useState<ThreatAnalysisResponse[]>([]);
  
  useEffect(() => {
    // WebSocket connection for real-time updates
    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws/analysis';
    let ws: WebSocket | null = null;
    
    const connect = () => {
      try {
        ws = new WebSocket(wsUrl);
        
        ws.onopen = () => {
          setIsConnected(true);
          console.log('Connected to analysis WebSocket');
        };
        
        ws.onmessage = (event) => {
          try {
            const update: ThreatAnalysisResponse = JSON.parse(event.data);
            setAnalysisUpdates(prev => [update, ...prev.slice(0, 9)]); // Keep last 10
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };
        
        ws.onclose = () => {
          setIsConnected(false);
          console.log('Disconnected from analysis WebSocket');
          // Attempt to reconnect after 5 seconds
          setTimeout(connect, 5000);
        };
        
        ws.onerror = (error) => {
          console.error('WebSocket error:', error);
        };
      } catch (error) {
        console.error('Failed to connect to WebSocket:', error);
        setTimeout(connect, 5000);
      }
    };
    
    connect();
    
    return () => {
      if (ws) {
        ws.close();
      }
    };
  }, []);
  
  return {
    isConnected,
    analysisUpdates,
    clearUpdates: () => setAnalysisUpdates([]),
  };
};

// Helper hook for analysis comparison
export const useAnalysisComparison = () => {
  const [comparisonData, setComparisonData] = useState<{
    baseline: ThreatAnalysisResponse | null;
    comparisons: ThreatAnalysisResponse[];
  }>({
    baseline: null,
    comparisons: [],
  });

  const setBaseline = (analysis: ThreatAnalysisResponse) => {
    setComparisonData(prev => ({ ...prev, baseline: analysis }));
  };

  const addComparison = (analysis: ThreatAnalysisResponse) => {
    setComparisonData(prev => ({
      ...prev,
      comparisons: [...prev.comparisons, analysis],
    }));
  };

  const removeComparison = (index: number) => {
    setComparisonData(prev => ({
      ...prev,
      comparisons: prev.comparisons.filter((_, i) => i !== index),
    }));
  };

  const clearComparisons = () => {
    setComparisonData({ baseline: null, comparisons: [] });
  };

  const calculateDifferences = () => {
    if (!comparisonData.baseline) return [];

    return comparisonData.comparisons.map(comparison => ({
      threat_score_diff: comparison.threat_score - comparisonData.baseline!.threat_score,
      level_changed: comparison.threat_level !== comparisonData.baseline!.threat_level,
      hash_match: comparison.deterministic_hash === comparisonData.baseline!.deterministic_hash,
      component_diffs: Object.entries(comparison.explanation.component_breakdown).map(([component, score]) => ({
        component,
        diff: score - (comparisonData.baseline!.explanation.component_breakdown[component] || 0),
      })),
    }));
  };

  return {
    ...comparisonData,
    setBaseline,
    addComparison,
    removeComparison,
    clearComparisons,
    calculateDifferences,
  };
};