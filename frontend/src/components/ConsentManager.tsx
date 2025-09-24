/**
 * Comprehensive Consent Management Interface
 * Provides transparent consent controls with GDPR compliance
 */

import React, { useState, useEffect, useCallback } from 'react';
import { 
  Shield, 
  Eye, 
  Lock,
  Download,
  Trash2,
  Settings,
  CheckCircle,
  AlertTriangle,
  Info,
  ExternalLink,
  Clock,
  Database,
  FileText,
  User,
  Zap,
  BarChart3
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { apiService } from '../services/apiService';

interface ConsentStatus {
  consent_exists: boolean;
  status: 'active' | 'revoked' | 'expired' | 'none';
  consent_id?: string;
  email?: string;
  granted_scopes: string[];
  granted_at?: string;
  updated_at?: string;
  data_processing: {
    subject_analysis: boolean;
    body_analysis: boolean;
    attachment_scanning: boolean;
    llm_processing: boolean;
    threat_intel_lookup: boolean;
    ai_analysis_opt_out: boolean;
    persistent_storage_opt_out: boolean;
  };
  privacy_settings: {
    allow_analytics: boolean;
    allow_performance_monitoring: boolean;
    share_threat_intelligence: boolean;
  };
  retention: {
    policy: string;
    effective_days: number;
    data_region: string;
  };
  data_artifacts: {
    total: number;
    active: number;
    expired: number;
  };
  legal_compliance: {
    gdpr_consent: boolean;
    ccpa_opt_out: boolean;
    privacy_policy_version: string;
    terms_version: string;
  };
  requires_consent: boolean;
}

interface ScopeInfo {
  scope: string;
  title: string;
  description: string;
  required: boolean;
  data_access: string[];
  purposes: string[];
  privacy_impact: 'Low' | 'Medium' | 'High';
}

const ConsentManager: React.FC = () => {
  const [consentStatus, setConsentStatus] = useState<ConsentStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [showDataExport, setShowDataExport] = useState(false);
  const [showRevocation, setShowRevocation] = useState(false);
  const [showScopeDetails, setShowScopeDetails] = useState(false);
  const [notification, setNotification] = useState<{type: 'success' | 'error' | 'info'; message: string} | null>(null);
  
  const { user, isAuthenticated } = useAuth();

  // Fetch consent status
  const fetchConsentStatus = useCallback(async () => {
    try {
      setLoading(true);
      const response = await apiService.get('/api/v1/consent/status');
      
      if (response.success) {
        setConsentStatus(response.data);
      } else {
        throw new Error(response.error || 'Failed to fetch consent status');
      }
    } catch (error) {
      console.error('Failed to fetch consent status:', error);
      setNotification({
        type: 'error',
        message: 'Failed to load consent information'
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      fetchConsentStatus();
    }
  }, [isAuthenticated, fetchConsentStatus]);

  // Update consent preferences
  const updateConsentPreferences = async (updates: Partial<ConsentStatus['data_processing'] & ConsentStatus['privacy_settings']>) => {
    try {
      setUpdating(true);
      
      const response = await apiService.patch('/api/v1/consent/preferences', updates);
      
      if (response.success) {
        await fetchConsentStatus(); // Refresh status
        setNotification({
          type: 'success',
          message: 'Consent preferences updated successfully'
        });
      } else {
        throw new Error(response.error || 'Failed to update preferences');
      }
    } catch (error) {
      console.error('Failed to update preferences:', error);
      setNotification({
        type: 'error',
        message: 'Failed to update consent preferences'
      });
    } finally {
      setUpdating(false);
    }
  };

  // Export user data (GDPR)
  const exportUserData = async () => {
    try {
      setLoading(true);
      const response = await apiService.get('/api/v1/consent/export');
      
      if (response.success) {
        // Create downloadable file
        const exportData = JSON.stringify(response.data.export_data, null, 2);
        const blob = new Blob([exportData], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishnet-data-export-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        setNotification({
          type: 'success',
          message: 'Data export downloaded successfully'
        });
      } else {
        throw new Error(response.error || 'Failed to export data');
      }
    } catch (error) {
      console.error('Failed to export data:', error);
      setNotification({
        type: 'error',
        message: 'Failed to export user data'
      });
    } finally {
      setLoading(false);
      setShowDataExport(false);
    }
  };

  // Revoke consent
  const revokeConsent = async (reason: string, cleanupData: boolean = true) => {
    try {
      setUpdating(true);
      
      const response = await apiService.post('/api/v1/consent/revoke', {
        revocation_reason: reason,
        cleanup_data: cleanupData,
        immediate_revocation: true
      });
      
      if (response.success) {
        await fetchConsentStatus(); // Refresh status
        setNotification({
          type: 'info',
          message: 'Consent has been revoked. Your data will be deleted as requested.'
        });
      } else {
        throw new Error(response.error || 'Failed to revoke consent');
      }
    } catch (error) {
      console.error('Failed to revoke consent:', error);
      setNotification({
        type: 'error',
        message: 'Failed to revoke consent'
      });
    } finally {
      setUpdating(false);
      setShowRevocation(false);
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="p-6 text-center">
        <Shield className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-4 text-lg font-medium text-gray-900">Authentication Required</h3>
        <p className="mt-2 text-gray-600">Please sign in to manage your consent preferences.</p>
      </div>
    );
  }

  if (loading && !consentStatus) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <span className="ml-3 text-gray-600">Loading consent information...</span>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      {/* Notification */}
      {notification && (
        <div className={`p-4 rounded-lg border ${
          notification.type === 'error' ? 'bg-red-50 border-red-200 text-red-800' :
          notification.type === 'success' ? 'bg-green-50 border-green-200 text-green-800' :
          'bg-blue-50 border-blue-200 text-blue-800'
        }`}>
          <div className="flex justify-between items-center">
            <span>{notification.message}</span>
            <button
              onClick={() => setNotification(null)}
              className="text-gray-500 hover:text-gray-700"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-blue-600" />
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Consent & Privacy Management</h1>
              <p className="text-gray-600">Manage your data processing permissions and privacy preferences</p>
            </div>
          </div>
          
          {consentStatus && (
            <div className={`px-3 py-1 rounded-full text-sm font-medium ${
              consentStatus.status === 'active' ? 'bg-green-100 text-green-800' :
              consentStatus.status === 'revoked' ? 'bg-red-100 text-red-800' :
              consentStatus.status === 'expired' ? 'bg-yellow-100 text-yellow-800' :
              'bg-gray-100 text-gray-800'
            }`}>
              {consentStatus.status === 'active' ? 'Consent Active' :
               consentStatus.status === 'revoked' ? 'Consent Revoked' :
               consentStatus.status === 'expired' ? 'Consent Expired' :
               'No Consent'}
            </div>
          )}
        </div>
      </div>

      {!consentStatus?.consent_exists ? (
        /* No Consent State */
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="h-6 w-6 text-yellow-600" />
            <div>
              <h3 className="text-lg font-medium text-yellow-800">Gmail Access Not Connected</h3>
              <p className="text-yellow-700">You need to grant consent to connect your Gmail account for phishing protection.</p>
            </div>
          </div>
          <div className="mt-4">
            <button
              className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center space-x-2"
              onClick={() => window.location.href = '/gmail-connect'}
            >
              <Shield className="h-4 w-4" />
              <span>Connect Gmail & Grant Consent</span>
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Consent Overview */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
              <Eye className="h-5 w-5 mr-2 text-blue-600" />
              Consent Overview
            </h2>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center p-4 bg-blue-50 rounded-lg">
                <User className="h-8 w-8 mx-auto text-blue-600 mb-2" />
                <div className="text-sm font-medium text-gray-700">Connected Account</div>
                <div className="text-lg font-semibold text-blue-900">{consentStatus.email}</div>
              </div>
              
              <div className="text-center p-4 bg-green-50 rounded-lg">
                <Clock className="h-8 w-8 mx-auto text-green-600 mb-2" />
                <div className="text-sm font-medium text-gray-700">Consent Granted</div>
                <div className="text-lg font-semibold text-green-900">
                  {consentStatus.granted_at ? new Date(consentStatus.granted_at).toLocaleDateString() : 'N/A'}
                </div>
              </div>
              
              <div className="text-center p-4 bg-purple-50 rounded-lg">
                <Database className="h-8 w-8 mx-auto text-purple-600 mb-2" />
                <div className="text-sm font-medium text-gray-700">Data Artifacts</div>
                <div className="text-lg font-semibold text-purple-900">
                  {consentStatus.data_artifacts.active} active
                </div>
              </div>
            </div>
          </div>

          {/* Data Processing Permissions */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
              <Settings className="h-5 w-5 mr-2 text-blue-600" />
              Data Processing Permissions
            </h2>
            
            <div className="space-y-4">
              {/* Email Analysis */}
              <div className="border border-gray-200 rounded-lg p-4">
                <h3 className="font-medium text-gray-900 mb-3">Email Content Analysis</h3>
                <div className="space-y-3">
                  <label className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <FileText className="h-5 w-5 text-gray-400" />
                      <div>
                        <div className="font-medium">Subject Line Analysis</div>
                        <div className="text-sm text-gray-600">Analyze email subjects for phishing indicators</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={consentStatus.data_processing.subject_analysis}
                      onChange={(e) => updateConsentPreferences({ allow_subject_analysis: e.target.checked })}
                      disabled={updating}
                      className="h-4 w-4 text-blue-600 rounded border-gray-300"
                    />
                  </label>
                  
                  <label className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <FileText className="h-5 w-5 text-gray-400" />
                      <div>
                        <div className="font-medium">Email Body Analysis</div>
                        <div className="text-sm text-gray-600">Analyze email content and links for threats</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={consentStatus.data_processing.body_analysis}
                      onChange={(e) => updateConsentPreferences({ allow_body_analysis: e.target.checked })}
                      disabled={updating}
                      className="h-4 w-4 text-blue-600 rounded border-gray-300"
                    />
                  </label>
                  
                  <label className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <Database className="h-5 w-5 text-gray-400" />
                      <div>
                        <div className="font-medium">Attachment Scanning</div>
                        <div className="text-sm text-gray-600">Scan email attachments for malware</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={consentStatus.data_processing.attachment_scanning}
                      onChange={(e) => updateConsentPreferences({ allow_attachment_scanning: e.target.checked })}
                      disabled={updating}
                      className="h-4 w-4 text-blue-600 rounded border-gray-300"
                    />
                  </label>
                </div>
              </div>

              {/* AI Processing */}
              <div className="border border-gray-200 rounded-lg p-4">
                <h3 className="font-medium text-gray-900 mb-3">AI & Machine Learning</h3>
                <div className="space-y-3">
                  <label className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <Zap className="h-5 w-5 text-gray-400" />
                      <div>
                        <div className="font-medium">AI/LLM Processing</div>
                        <div className="text-sm text-gray-600">Use advanced AI models for threat detection</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={consentStatus.data_processing.llm_processing && !consentStatus.data_processing.ai_analysis_opt_out}
                      onChange={(e) => updateConsentPreferences({ 
                        allow_llm_processing: e.target.checked,
                        opt_out_ai_analysis: !e.target.checked 
                      })}
                      disabled={updating}
                      className="h-4 w-4 text-blue-600 rounded border-gray-300"
                    />
                  </label>
                  
                  <label className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <Shield className="h-5 w-5 text-gray-400" />
                      <div>
                        <div className="font-medium">Threat Intelligence Lookup</div>
                        <div className="text-sm text-gray-600">Check URLs and domains against threat databases</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={consentStatus.data_processing.threat_intel_lookup}
                      onChange={(e) => updateConsentPreferences({ allow_threat_intel_lookup: e.target.checked })}
                      disabled={updating}
                      className="h-4 w-4 text-blue-600 rounded border-gray-300"
                    />
                  </label>
                </div>
              </div>

              {/* Data Storage */}
              <div className="border border-gray-200 rounded-lg p-4">
                <h3 className="font-medium text-gray-900 mb-3">Data Storage & Retention</h3>
                <div className="space-y-3">
                  <label className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <Database className="h-5 w-5 text-gray-400" />
                      <div>
                        <div className="font-medium">Allow Data Storage</div>
                        <div className="text-sm text-gray-600">Store analysis results for {consentStatus.retention.effective_days} days</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={!consentStatus.data_processing.persistent_storage_opt_out}
                      onChange={(e) => updateConsentPreferences({ opt_out_persistent_storage: !e.target.checked })}
                      disabled={updating}
                      className="h-4 w-4 text-blue-600 rounded border-gray-300"
                    />
                  </label>
                </div>
              </div>

              {/* Privacy Preferences */}
              <div className="border border-gray-200 rounded-lg p-4">
                <h3 className="font-medium text-gray-900 mb-3">Privacy & Analytics</h3>
                <div className="space-y-3">
                  <label className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <BarChart3 className="h-5 w-5 text-gray-400" />
                      <div>
                        <div className="font-medium">Usage Analytics</div>
                        <div className="text-sm text-gray-600">Help improve the service with anonymous usage data</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={consentStatus.privacy_settings.allow_analytics}
                      onChange={(e) => updateConsentPreferences({ allow_analytics: e.target.checked })}
                      disabled={updating}
                      className="h-4 w-4 text-blue-600 rounded border-gray-300"
                    />
                  </label>
                  
                  <label className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <Shield className="h-5 w-5 text-gray-400" />
                      <div>
                        <div className="font-medium">Threat Intelligence Sharing</div>
                        <div className="text-sm text-gray-600">Share anonymous threat indicators to protect others</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={consentStatus.privacy_settings.share_threat_intelligence}
                      onChange={(e) => updateConsentPreferences({ share_threat_intelligence: e.target.checked })}
                      disabled={updating}
                      className="h-4 w-4 text-blue-600 rounded border-gray-300"
                    />
                  </label>
                </div>
              </div>
            </div>
          </div>

          {/* Legal Rights & Actions */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center">
              <Lock className="h-5 w-5 mr-2 text-blue-600" />
              Your Legal Rights (GDPR)
            </h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <button
                onClick={() => setShowDataExport(true)}
                className="p-4 border border-gray-200 rounded-lg hover:bg-gray-50 text-left"
              >
                <div className="flex items-center space-x-3">
                  <Download className="h-5 w-5 text-blue-600" />
                  <div>
                    <div className="font-medium text-gray-900">Export Your Data</div>
                    <div className="text-sm text-gray-600">Download all your personal data (GDPR Article 20)</div>
                  </div>
                </div>
              </button>
              
              <button
                onClick={() => setShowRevocation(true)}
                className="p-4 border border-red-200 rounded-lg hover:bg-red-50 text-left"
              >
                <div className="flex items-center space-x-3">
                  <Trash2 className="h-5 w-5 text-red-600" />
                  <div>
                    <div className="font-medium text-red-900">Revoke Consent & Delete Data</div>
                    <div className="text-sm text-red-600">Withdraw consent and delete all data (GDPR Article 17)</div>
                  </div>
                </div>
              </button>
            </div>
            
            <div className="mt-4 p-4 bg-blue-50 rounded-lg">
              <div className="flex items-start space-x-3">
                <Info className="h-5 w-5 text-blue-600 mt-0.5" />
                <div className="text-sm">
                  <div className="font-medium text-blue-900">Your Rights Include:</div>
                  <ul className="mt-2 space-y-1 text-blue-800">
                    <li>• Right to access your personal data</li>
                    <li>• Right to rectify inaccurate data</li>
                    <li>• Right to erase your data (right to be forgotten)</li>
                    <li>• Right to restrict processing</li>
                    <li>• Right to data portability</li>
                    <li>• Right to object to processing</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>

          {/* Data Export Modal */}
          {showDataExport && (
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
              <div className="bg-white rounded-lg p-6 max-w-md mx-4">
                <div className="flex items-center space-x-3 mb-4">
                  <Download className="h-6 w-6 text-blue-600" />
                  <h3 className="text-lg font-semibold">Export Your Data</h3>
                </div>
                
                <div className="space-y-4 text-sm text-gray-600">
                  <p>
                    This will download a JSON file containing all your personal data processed by PhishNet, including:
                  </p>
                  
                  <ul className="space-y-1 ml-4">
                    <li>• Consent records and preferences</li>
                    <li>• Data processing activity logs</li>
                    <li>• Email analysis metadata ({consentStatus.data_artifacts.total} items)</li>
                    <li>• Account and usage information</li>
                  </ul>
                  
                  <p className="text-xs text-gray-500">
                    This export complies with GDPR Article 20 (Right to Data Portability)
                  </p>
                </div>
                
                <div className="flex space-x-3 mt-6">
                  <button
                    onClick={exportUserData}
                    disabled={loading}
                    className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
                  >
                    {loading ? 'Preparing...' : 'Download Export'}
                  </button>
                  <button
                    onClick={() => setShowDataExport(false)}
                    className="border border-gray-300 px-4 py-2 rounded-lg hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Consent Revocation Modal */}
          {showRevocation && (
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
              <div className="bg-white rounded-lg p-6 max-w-md mx-4">
                <div className="flex items-center space-x-3 mb-4">
                  <AlertTriangle className="h-6 w-6 text-red-600" />
                  <h3 className="text-lg font-semibold text-red-900">Revoke Consent</h3>
                </div>
                
                <div className="space-y-4 text-sm text-gray-600">
                  <p className="text-red-700">
                    <strong>Warning:</strong> This action cannot be undone. Revoking consent will:
                  </p>
                  
                  <ul className="space-y-1 ml-4 text-red-600">
                    <li>• Immediately disconnect your Gmail account</li>
                    <li>• Delete all stored analysis data and metadata</li>
                    <li>• Stop all email monitoring and protection</li>
                    <li>• Remove your account and preferences</li>
                  </ul>
                  
                  <p className="text-xs text-gray-500">
                    This complies with GDPR Article 17 (Right to Erasure) and Article 7 (Withdrawal of Consent)
                  </p>
                </div>
                
                <div className="flex space-x-3 mt-6">
                  <button
                    onClick={() => revokeConsent("User-requested revocation", true)}
                    disabled={updating}
                    className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 disabled:opacity-50"
                  >
                    {updating ? 'Revoking...' : 'Revoke Consent & Delete Data'}
                  </button>
                  <button
                    onClick={() => setShowRevocation(false)}
                    className="border border-gray-300 px-4 py-2 rounded-lg hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ConsentManager;