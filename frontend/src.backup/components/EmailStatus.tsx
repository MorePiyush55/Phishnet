import React from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Clock, 
  CheckCircle, 
  XCircle,
  Eye,
  Scan,
  AlertCircle,
  Info
} from 'lucide-react';

interface EmailStatusProps {
  status: 'scanning' | 'safe' | 'suspicious' | 'malicious' | 'quarantined' | 'pending';
  riskScore: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  confidenceScore?: number;
  aiVerdict?: string;
  vtScore?: string;
  explanation?: string;
  showDetails?: boolean;
  compact?: boolean;
}

interface StatusConfig {
  icon: React.ReactNode;
  color: string;
  bgColor: string;
  borderColor: string;
  label: string;
  description: string;
}

const getStatusConfig = (status: EmailStatusProps['status']): StatusConfig => {
  switch (status) {
    case 'scanning':
      return {
        icon: <Scan className="h-4 w-4 animate-spin" />,
        color: 'text-blue-600',
        bgColor: 'bg-blue-50',
        borderColor: 'border-blue-200',
        label: 'Scanning',
        description: 'Email is being analyzed for threats'
      };
    case 'safe':
      return {
        icon: <CheckCircle className="h-4 w-4" />,
        color: 'text-green-600',
        bgColor: 'bg-green-50',
        borderColor: 'border-green-200',
        label: 'Safe',
        description: 'No threats detected in this email'
      };
    case 'suspicious':
      return {
        icon: <AlertTriangle className="h-4 w-4" />,
        color: 'text-yellow-600',
        bgColor: 'bg-yellow-50',
        borderColor: 'border-yellow-200',
        label: 'Suspicious',
        description: 'Potential threats detected, requires review'
      };
    case 'malicious':
      return {
        icon: <XCircle className="h-4 w-4" />,
        color: 'text-red-600',
        bgColor: 'bg-red-50',
        borderColor: 'border-red-200',
        label: 'Malicious',
        description: 'Confirmed threats detected'
      };
    case 'quarantined':
      return {
        icon: <Shield className="h-4 w-4" />,
        color: 'text-purple-600',
        bgColor: 'bg-purple-50',
        borderColor: 'border-purple-200',
        label: 'Quarantined',
        description: 'Email has been isolated for security'
      };
    default:
      return {
        icon: <Clock className="h-4 w-4" />,
        color: 'text-gray-600',
        bgColor: 'bg-gray-50',
        borderColor: 'border-gray-200',
        label: 'Pending',
        description: 'Email is queued for analysis'
      };
  }
};

const getRiskScoreColor = (score: number): string => {
  if (score >= 80) return 'text-red-600';
  if (score >= 60) return 'text-orange-600';
  if (score >= 40) return 'text-yellow-600';
  return 'text-green-600';
};

const getRiskLevelConfig = (level: EmailStatusProps['riskLevel']) => {
  switch (level) {
    case 'critical':
      return { color: 'bg-red-500', label: 'Critical' };
    case 'high':
      return { color: 'bg-orange-500', label: 'High' };
    case 'medium':
      return { color: 'bg-yellow-500', label: 'Medium' };
    case 'low':
      return { color: 'bg-green-500', label: 'Low' };
    default:
      return { color: 'bg-gray-500', label: 'Unknown' };
  }
};

export const EmailStatus: React.FC<EmailStatusProps> = ({
  status,
  riskScore,
  riskLevel,
  confidenceScore,
  aiVerdict,
  vtScore,
  explanation,
  showDetails = false,
  compact = false
}) => {
  const statusConfig = getStatusConfig(status);
  const riskConfig = getRiskLevelConfig(riskLevel);

  if (compact) {
    return (
      <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${statusConfig.color} ${statusConfig.bgColor} ${statusConfig.borderColor} border`}>
        {statusConfig.icon}
        <span className="ml-1">{statusConfig.label}</span>
        <span className={`ml-2 ${getRiskScoreColor(riskScore)}`}>
          {riskScore}%
        </span>
      </div>
    );
  }

  return (
    <div className={`rounded-lg border ${statusConfig.borderColor} ${statusConfig.bgColor} p-4`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-2">
          <div className={statusConfig.color}>
            {statusConfig.icon}
          </div>
          <span className={`font-semibold ${statusConfig.color}`}>
            {statusConfig.label}
          </span>
        </div>
        
        <div className="flex items-center space-x-2">
          {/* Risk Score */}
          <div className="text-right">
            <div className={`text-lg font-bold ${getRiskScoreColor(riskScore)}`}>
              {riskScore}%
            </div>
            <div className="text-xs text-gray-500">Risk Score</div>
          </div>
          
          {/* Risk Level Badge */}
          <div className={`px-2 py-1 rounded text-xs font-medium text-white ${riskConfig.color}`}>
            {riskConfig.label}
          </div>
        </div>
      </div>

      {/* Description */}
      <p className="text-sm text-gray-600 mb-3">
        {statusConfig.description}
      </p>

      {/* Confidence Score */}
      {confidenceScore !== undefined && (
        <div className="mb-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-500">Confidence</span>
            <span className="font-medium">{confidenceScore}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
            <div 
              className={`h-2 rounded-full ${confidenceScore >= 80 ? 'bg-green-500' : confidenceScore >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`}
              style={{ width: `${confidenceScore}%` }}
            ></div>
          </div>
        </div>
      )}

      {/* AI Verdict */}
      {aiVerdict && (
        <div className="mb-3 p-2 bg-white rounded border">
          <div className="flex items-start space-x-2">
            <Info className="h-4 w-4 text-blue-500 mt-0.5 flex-shrink-0" />
            <div>
              <div className="text-xs font-medium text-gray-500 mb-1">AI Analysis</div>
              <div className="text-sm text-gray-700">{aiVerdict}</div>
            </div>
          </div>
        </div>
      )}

      {/* VirusTotal Score */}
      {vtScore && (
        <div className="mb-3 p-2 bg-white rounded border">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Eye className="h-4 w-4 text-purple-500" />
              <span className="text-xs font-medium text-gray-500">VirusTotal</span>
            </div>
            <span className="text-sm font-medium text-gray-700">{vtScore}</span>
          </div>
        </div>
      )}

      {/* Detailed Explanation */}
      {showDetails && explanation && (
        <div className="mt-3 p-3 bg-white rounded border">
          <div className="text-xs font-medium text-gray-500 mb-2">Analysis Details</div>
          <div className="text-sm text-gray-700 leading-relaxed">
            {explanation}
          </div>
        </div>
      )}

      {/* Processing Indicators */}
      {status === 'scanning' && (
        <div className="mt-3 flex items-center space-x-4 text-xs text-gray-500">
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
            <span>Content analysis</span>
          </div>
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse" style={{ animationDelay: '0.2s' }}></div>
            <span>Link scanning</span>
          </div>
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse" style={{ animationDelay: '0.4s' }}></div>
            <span>Threat intelligence</span>
          </div>
        </div>
      )}
    </div>
  );
};

// Specialized components for different use cases
export const EmailStatusBadge: React.FC<Pick<EmailStatusProps, 'status' | 'riskScore' | 'riskLevel'>> = (props) => (
  <EmailStatus {...props} compact={true} />
);

export const EmailStatusCard: React.FC<EmailStatusProps> = (props) => (
  <EmailStatus {...props} showDetails={true} />
);

// Status summary component for multiple emails
interface EmailStatusSummaryProps {
  emails: Array<{
    status: EmailStatusProps['status'];
    riskLevel: EmailStatusProps['riskLevel'];
  }>;
}

export const EmailStatusSummary: React.FC<EmailStatusSummaryProps> = ({ emails }) => {
  const statusCounts = emails.reduce((acc, email) => {
    acc[email.status] = (acc[email.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const riskCounts = emails.reduce((acc, email) => {
    acc[email.riskLevel] = (acc[email.riskLevel] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="grid grid-cols-2 gap-4">
      {/* Status Distribution */}
      <div className="bg-white rounded-lg border p-4">
        <h3 className="text-sm font-medium text-gray-700 mb-3">Status Distribution</h3>
        <div className="space-y-2">
          {Object.entries(statusCounts).map(([status, count]) => {
            const config = getStatusConfig(status as EmailStatusProps['status']);
            return (
              <div key={status} className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <div className={config.color}>
                    {config.icon}
                  </div>
                  <span className="text-sm text-gray-600">{config.label}</span>
                </div>
                <span className="text-sm font-medium">{count}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Risk Distribution */}
      <div className="bg-white rounded-lg border p-4">
        <h3 className="text-sm font-medium text-gray-700 mb-3">Risk Distribution</h3>
        <div className="space-y-2">
          {Object.entries(riskCounts).map(([level, count]) => {
            const config = getRiskLevelConfig(level as EmailStatusProps['riskLevel']);
            return (
              <div key={level} className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <div className={`w-3 h-3 rounded-full ${config.color}`}></div>
                  <span className="text-sm text-gray-600">{config.label}</span>
                </div>
                <span className="text-sm font-medium">{count}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
