import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Shield, 
  AlertTriangle, 
  TrendingUp, 
  Eye, 
  BarChart3, 
  Clock,
  CheckCircle,
  XCircle,
  HelpCircle
} from 'lucide-react';

interface ThreatExplanationProps {
  threatAnalysis: {
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
  };
}

const ThreatLevelBadge: React.FC<{ level: string; score: number }> = ({ level, score }) => {
  const getVariant = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'warning';
      case 'low': return 'secondary';
      case 'safe': return 'success';
      default: return 'secondary';
    }
  };

  const getIcon = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
      case 'high':
        return <XCircle className="h-4 w-4" />;
      case 'medium':
        return <AlertTriangle className="h-4 w-4" />;
      case 'low':
        return <HelpCircle className="h-4 w-4" />;
      case 'safe':
        return <CheckCircle className="h-4 w-4" />;
      default:
        return <Shield className="h-4 w-4" />;
    }
  };

  return (
    <Badge variant={getVariant(level)} className="flex items-center gap-2">
      {getIcon(level)}
      {level.toUpperCase()} ({(score * 100).toFixed(1)}%)
    </Badge>
  );
};

const ConfidenceBand: React.FC<{ 
  confidenceBand: { 
    lower_bound: number; 
    upper_bound: number; 
    confidence_level: number; 
  };
  threatScore: number;
}> = ({ confidenceBand, threatScore }) => {
  const { lower_bound, upper_bound, confidence_level } = confidenceBand;
  const range = upper_bound - lower_bound;
  const position = ((threatScore - lower_bound) / range) * 100;

  return (
    <div className="space-y-2">
      <div className="flex justify-between text-sm text-gray-600">
        <span>Confidence: {(confidence_level * 100).toFixed(1)}%</span>
        <span>Range: {(range * 100).toFixed(1)}%</span>
      </div>
      <div className="relative h-6 bg-gray-200 rounded-full">
        {/* Confidence band */}
        <div 
          className="absolute h-full bg-blue-200 rounded-full"
          style={{
            left: `${lower_bound * 100}%`,
            width: `${range * 100}%`
          }}
        />
        {/* Actual score marker */}
        <div 
          className="absolute top-0 h-full w-1 bg-red-500"
          style={{ left: `${threatScore * 100}%` }}
        />
        {/* Scale markers */}
        <div className="absolute inset-0 flex justify-between items-center px-1 text-xs">
          <span>0%</span>
          <span>25%</span>
          <span>50%</span>
          <span>75%</span>
          <span>100%</span>
        </div>
      </div>
      <div className="text-xs text-gray-500 text-center">
        Actual Score: {(threatScore * 100).toFixed(1)}% | 
        Confidence Band: {(lower_bound * 100).toFixed(1)}% - {(upper_bound * 100).toFixed(1)}%
      </div>
    </div>
  );
};

const ComponentBreakdownChart: React.FC<{ 
  breakdown: Record<string, number>;
  totalContribution: number;
}> = ({ breakdown, totalContribution }) => {
  const sortedComponents = Object.entries(breakdown)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8); // Limit to top 8 components

  return (
    <div className="space-y-3">
      {sortedComponents.map(([component, contribution]) => {
        const percentage = totalContribution > 0 ? (contribution / totalContribution) * 100 : 0;
        const displayPercentage = Math.max(percentage, 0.5); // Ensure visibility
        
        return (
          <div key={component} className="space-y-1">
            <div className="flex justify-between text-sm">
              <span className="font-medium capitalize">
                {component.replace(/_/g, ' ')}
              </span>
              <span className="text-gray-600">
                {percentage.toFixed(1)}%
              </span>
            </div>
            <Progress 
              value={displayPercentage} 
              className="h-2"
            />
          </div>
        );
      })}
    </div>
  );
};

const TopSignalsTable: React.FC<{ signals: ThreatExplanationProps['threatAnalysis']['explanation']['top_signals'] }> = ({ signals }) => {
  return (
    <div className="space-y-4">
      {signals.slice(0, 5).map((signal, index) => (
        <Card key={index} className="border-l-4 border-l-red-500">
          <CardContent className="pt-4">
            <div className="flex justify-between items-start mb-2">
              <div className="flex-1">
                <h4 className="font-semibold text-sm">{signal.description}</h4>
                <p className="text-xs text-gray-600 mt-1">
                  Component: <Badge variant="outline">{signal.component}</Badge>
                </p>
              </div>
              <div className="text-right">
                <div className="text-lg font-bold text-red-600">
                  {(signal.contribution * 100).toFixed(2)}%
                </div>
                <div className="text-xs text-gray-500">contribution</div>
              </div>
            </div>
            
            {signal.evidence && signal.evidence.length > 0 && (
              <div className="mt-3 pt-3 border-t">
                <p className="text-xs font-medium text-gray-700 mb-1">Evidence:</p>
                <ul className="text-xs text-gray-600 space-y-1">
                  {signal.evidence.slice(0, 3).map((evidence, evidenceIndex) => (
                    <li key={evidenceIndex} className="flex items-start">
                      <span className="inline-block w-1 h-1 bg-gray-400 rounded-full mt-2 mr-2 flex-shrink-0" />
                      {evidence}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
};

const CertaintyFactorsGrid: React.FC<{ factors: Record<string, number> }> = ({ factors }) => {
  const factorDescriptions: Record<string, string> = {
    component_agreement: "How much analysis components agree with each other",
    data_coverage: "Percentage of available analysis components used",
    signal_strength: "Overall strength of detected threat signals",
    confidence_consistency: "Consistency of confidence scores across components"
  };

  return (
    <div className="grid grid-cols-2 gap-4">
      {Object.entries(factors).map(([factor, value]) => (
        <Card key={factor} className="p-4">
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <h4 className="font-medium text-sm capitalize">
                {factor.replace(/_/g, ' ')}
              </h4>
              <span className="text-lg font-bold">
                {(value * 100).toFixed(0)}%
              </span>
            </div>
            <Progress value={value * 100} className="h-2" />
            <p className="text-xs text-gray-600">
              {factorDescriptions[factor] || "Analysis certainty factor"}
            </p>
          </div>
        </Card>
      ))}
    </div>
  );
};

const MetadataPanel: React.FC<{ 
  metadata: ThreatExplanationProps['threatAnalysis']['metadata'];
  hash: string;
}> = ({ metadata, hash }) => {
  const formatDate = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <Card className="p-4">
          <div className="flex items-center space-x-2">
            <Clock className="h-4 w-4 text-gray-500" />
            <div>
              <p className="text-sm font-medium">Processing Time</p>
              <p className="text-lg font-bold">{metadata.processing_time.toFixed(3)}s</p>
            </div>
          </div>
        </Card>
        
        <Card className="p-4">
          <div className="flex items-center space-x-2">
            <TrendingUp className="h-4 w-4 text-gray-500" />
            <div>
              <p className="text-sm font-medium">Threshold Profile</p>
              <p className="text-lg font-bold capitalize">{metadata.threshold_profile}</p>
            </div>
          </div>
        </Card>
      </div>
      
      <Card className="p-4">
        <h4 className="font-medium mb-2">Analysis Details</h4>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span>Timestamp:</span>
            <span className="font-mono text-xs">{formatDate(metadata.timestamp)}</span>
          </div>
          <div className="flex justify-between">
            <span>Version:</span>
            <span className="font-mono">{metadata.version}</span>
          </div>
          <div className="flex justify-between">
            <span>Deterministic Hash:</span>
            <span className="font-mono text-xs bg-gray-100 px-2 py-1 rounded">
              {hash}
            </span>
          </div>
        </div>
      </Card>
    </div>
  );
};

export const ThreatExplanationDashboard: React.FC<ThreatExplanationProps> = ({ threatAnalysis }) => {
  const [activeTab, setActiveTab] = useState('overview');
  
  const totalContribution = Object.values(threatAnalysis.explanation.component_breakdown)
    .reduce((sum, contrib) => sum + contrib, 0);

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Threat Analysis Explanation</h1>
          <p className="text-gray-600">Detailed breakdown of security assessment</p>
        </div>
        <ThreatLevelBadge 
          level={threatAnalysis.threat_level} 
          score={threatAnalysis.threat_score}
        />
      </div>

      {/* Quick Status Alert */}
      <Alert className={
        threatAnalysis.threat_level === 'high' || threatAnalysis.threat_level === 'critical' 
          ? 'border-red-500 bg-red-50' 
          : threatAnalysis.threat_level === 'medium'
          ? 'border-yellow-500 bg-yellow-50'
          : 'border-green-500 bg-green-50'
      }>
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          <strong>Recommended Action:</strong> {threatAnalysis.recommended_action.toUpperCase()}
          <br />
          <span className="text-sm">{threatAnalysis.explanation.reasoning}</span>
        </AlertDescription>
      </Alert>

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="signals">Top Signals</TabsTrigger>
          <TabsTrigger value="components">Components</TabsTrigger>
          <TabsTrigger value="confidence">Confidence</TabsTrigger>
          <TabsTrigger value="metadata">Details</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Confidence Band */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Eye className="h-5 w-5" />
                  <span>Confidence Assessment</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ConfidenceBand 
                  confidenceBand={threatAnalysis.explanation.confidence_band}
                  threatScore={threatAnalysis.threat_score}
                />
              </CardContent>
            </Card>

            {/* Component Breakdown */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <BarChart3 className="h-5 w-5" />
                  <span>Component Contributions</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ComponentBreakdownChart 
                  breakdown={threatAnalysis.explanation.component_breakdown}
                  totalContribution={totalContribution}
                />
              </CardContent>
            </Card>
          </div>

          {/* Risk Factors */}
          {threatAnalysis.explanation.risk_factors.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Key Risk Factors</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {threatAnalysis.explanation.risk_factors.map((factor, index) => (
                    <Badge key={index} variant="destructive">
                      {factor}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="signals">
          <Card>
            <CardHeader>
              <CardTitle>Top Contributing Signals</CardTitle>
              <p className="text-sm text-gray-600">
                These signals had the highest impact on the final threat score
              </p>
            </CardHeader>
            <CardContent>
              <TopSignalsTable signals={threatAnalysis.explanation.top_signals} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="components">
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Analysis Component Results</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {threatAnalysis.components.map((component, index) => (
                    <Card key={index} className="border-l-4 border-l-blue-500">
                      <CardContent className="pt-4">
                        <div className="flex justify-between items-start mb-3">
                          <div>
                            <h4 className="font-semibold capitalize">
                              {component.type.replace(/_/g, ' ')}
                            </h4>
                            <p className="text-sm text-gray-600">
                              Processing: {component.processing_time.toFixed(3)}s
                            </p>
                          </div>
                          <div className="text-right">
                            <div className="text-lg font-bold">
                              {(component.score * 100).toFixed(1)}%
                            </div>
                            <div className="text-sm text-gray-600">
                              Confidence: {(component.confidence * 100).toFixed(1)}%
                            </div>
                          </div>
                        </div>
                        
                        <div className="space-y-2">
                          <Progress value={component.score * 100} className="h-2" />
                          <div className="flex flex-wrap gap-1">
                            {component.signals.slice(0, 5).map((signal, signalIndex) => (
                              <Badge key={signalIndex} variant="outline" className="text-xs">
                                {signal}
                              </Badge>
                            ))}
                            {component.signals.length > 5 && (
                              <Badge variant="secondary" className="text-xs">
                                +{component.signals.length - 5} more
                              </Badge>
                            )}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="confidence">
          <Card>
            <CardHeader>
              <CardTitle>Certainty Factors</CardTitle>
              <p className="text-sm text-gray-600">
                Factors that influence the confidence in this threat assessment
              </p>
            </CardHeader>
            <CardContent>
              <CertaintyFactorsGrid factors={threatAnalysis.explanation.certainty_factors} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="metadata">
          <MetadataPanel 
            metadata={threatAnalysis.metadata}
            hash={threatAnalysis.deterministic_hash}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
};