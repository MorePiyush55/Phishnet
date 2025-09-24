import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { 
  Shield, 
  Download, 
  Trash2, 
  AlertTriangle, 
  CheckCircle, 
  Info,
  Settings,
  Eye,
  FileText,
  Clock
} from 'lucide-react';

interface ConsentPreferences {
  allowSubjectAnalysis: boolean;
  allowBodyAnalysis: boolean;
  allowAttachmentScanning: boolean;
  allowLLMProcessing: boolean;
  allowThreatIntelLookup: boolean;
  optOutAIAnalysis: boolean;
}

interface ConsentStatus {
  isValid: boolean;
  grantedScopes: string[];
  expiresAt: string | null;
  lastUpdated: string;
  preferences: ConsentPreferences;
}

interface GDPRRights {
  canExportData: boolean;
  canDeleteData: boolean;
  canRectifyData: boolean;
  canRestrictProcessing: boolean;
}

export const ConsentManager: React.FC = () => {
  const [consentStatus, setConsentStatus] = useState<ConsentStatus | null>(null);
  const [gdprRights, setGdprRights] = useState<GDPRRights>({
    canExportData: true,
    canDeleteData: true,
    canRectifyData: true,
    canRestrictProcessing: true
  });
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);

  useEffect(() => {
    loadConsentStatus();
  }, []);

  const loadConsentStatus = async () => {
    try {
      const response = await fetch('/api/v1/consent/status');
      if (response.ok) {
        const data = await response.json();
        setConsentStatus(data.consent_status);
      }
    } catch (error) {
      console.error('Failed to load consent status:', error);
    } finally {
      setLoading(false);
    }
  };

  const updateConsentPreferences = async (preferences: Partial<ConsentPreferences>) => {
    setUpdating(true);
    try {
      const response = await fetch('/api/v1/consent/preferences', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(preferences)
      });

      if (response.ok) {
        await loadConsentStatus();
      }
    } catch (error) {
      console.error('Failed to update preferences:', error);
    } finally {
      setUpdating(false);
    }
  };

  const handleDataExport = async () => {
    try {
      const response = await fetch('/api/v1/consent/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: 'json', include_all: true })
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `my-data-export-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (error) {
      console.error('Data export failed:', error);
    }
    setShowExportModal(false);
  };

  const revokeConsent = async () => {
    try {
      const response = await fetch('/api/v1/consent/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ revoke_all: true })
      });

      if (response.ok) {
        await loadConsentStatus();
      }
    } catch (error) {
      console.error('Consent revocation failed:', error);
    }
    setShowDeleteModal(false);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      <div className="flex items-center space-x-3 mb-6">
        <Shield className="h-8 w-8 text-blue-600" />
        <h1 className="text-3xl font-bold text-gray-900">Consent Management</h1>
      </div>

      {/* Consent Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <CheckCircle className="h-5 w-5 text-green-600" />
            <span>Current Consent Status</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {consentStatus ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="font-medium">Status:</span>
                <Badge variant={consentStatus.isValid ? "default" : "destructive"}>
                  {consentStatus.isValid ? "Active" : "Expired"}
                </Badge>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="font-medium">Granted Scopes:</span>
                <div className="flex space-x-2">
                  {consentStatus.grantedScopes.map(scope => (
                    <Badge key={scope} variant="outline" className="text-xs">
                      {scope.split('/').pop()}
                    </Badge>
                  ))}
                </div>
              </div>

              {consentStatus.expiresAt && (
                <div className="flex items-center justify-between">
                  <span className="font-medium">Expires:</span>
                  <span className="text-sm text-gray-600">
                    {new Date(consentStatus.expiresAt).toLocaleDateString()}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>
                No active consent found. Please authorize access to use PhishNet scanning.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* scanning permissions & consent preferences */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Settings className="h-5 w-5 text-blue-600" />
            <span>Scanning Permissions & Consent Preferences</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div>
                <p className="font-medium">Subject Analysis</p>
                <p className="text-sm text-gray-600">Analyze email subject lines</p>
              </div>
              <Switch 
                checked={consentStatus?.preferences.allowSubjectAnalysis || false}
                onCheckedChange={(checked) => updateConsentPreferences({ allowSubjectAnalysis: checked })}
                disabled={updating}
              />
            </div>

            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div>
                <p className="font-medium">Body Analysis</p>
                <p className="text-sm text-gray-600">Analyze email content</p>
              </div>
              <Switch 
                checked={consentStatus?.preferences.allowBodyAnalysis || false}
                onCheckedChange={(checked) => updateConsentPreferences({ allowBodyAnalysis: checked })}
                disabled={updating}
              />
            </div>

            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div>
                <p className="font-medium">Attachment Scanning</p>
                <p className="text-sm text-gray-600">Scan email attachments</p>
              </div>
              <Switch 
                checked={consentStatus?.preferences.allowAttachmentScanning || false}
                onCheckedChange={(checked) => updateConsentPreferences({ allowAttachmentScanning: checked })}
                disabled={updating}
              />
            </div>

            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div>
                <p className="font-medium">AI Processing</p>
                <p className="text-sm text-gray-600">Use AI for threat analysis</p>
              </div>
              <Switch 
                checked={consentStatus?.preferences.allowLLMProcessing || false}
                onCheckedChange={(checked) => updateConsentPreferences({ allowLLMProcessing: checked })}
                disabled={updating}
              />
            </div>
          </div>

          <Alert>
            <Shield className="h-4 w-4" />
            <AlertDescription>
              All data processing is done securely and in compliance with GDPR. 
              You can modify these preferences at any time.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>

      {/* GDPR rights */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Eye className="h-5 w-5 text-blue-600" />
            <span>Your GDPR Rights</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-gray-600 mb-4">
            Under the General Data Protection Regulation (GDPR), you have the following rights regarding your personal data:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Button
              variant="outline"
              className="flex items-center justify-center space-x-2 h-auto p-4"
              onClick={() => setShowExportModal(true)}
              disabled={!gdprRights.canExportData}
            >
              <Download className="h-5 w-5" />
              <div className="text-left">
                <p className="font-medium">Export My Data</p>
                <p className="text-sm text-gray-600">Download all your data</p>
              </div>
            </Button>

            <Button
              variant="outline"
              className="flex items-center justify-center space-x-2 h-auto p-4 text-red-600 border-red-200 hover:bg-red-50"
              onClick={() => setShowDeleteModal(true)}
              disabled={!gdprRights.canDeleteData}
            >
              <Trash2 className="h-5 w-5" />
              <div className="text-left">
                <p className="font-medium">Delete My Data</p>
                <p className="text-sm text-gray-600">Revoke consent & delete</p>
              </div>
            </Button>
          </div>

          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-medium text-blue-900 mb-2">Legal Compliance</h4>
            <ul className="text-sm text-blue-800 space-y-1">
              <li>• Right to access your data (Article 15)</li>
              <li>• Right to data portability (Article 20)</li>
              <li>• Right to erasure/be forgotten (Article 17)</li>
              <li>• Right to rectification (Article 16)</li>
              <li>• Right to restrict processing (Article 18)</li>
            </ul>
          </div>
        </CardContent>
      </Card>

      {/* Export Modal */}
      {showExportModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <Card className="w-96">
            <CardHeader>
              <CardTitle>Export Your Data</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-gray-600">
                This will download all your personal data including consent records, scan results, and preferences.
              </p>
              <div className="flex space-x-3">
                <Button onClick={handleDataExport} className="flex-1">
                  <Download className="h-4 w-4 mr-2" />
                  Download
                </Button>
                <Button variant="outline" onClick={() => setShowExportModal(false)}>
                  Cancel
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Delete Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <Card className="w-96">
            <CardHeader>
              <CardTitle className="text-red-600">Delete Your Data</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  This action cannot be undone. All your data will be permanently deleted.
                </AlertDescription>
              </Alert>
              <p className="text-gray-600">
                This will revoke all consent and permanently delete your personal data from our systems.
              </p>
              <div className="flex space-x-3">
                <Button variant="destructive" onClick={revokeConsent} className="flex-1">
                  <Trash2 className="h-4 w-4 mr-2" />
                  Delete All Data
                </Button>
                <Button variant="outline" onClick={() => setShowDeleteModal(false)}>
                  Cancel
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};