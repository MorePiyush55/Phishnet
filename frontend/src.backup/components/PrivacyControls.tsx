import React, { useState } from 'react';
import { 
  Shield, 
  Lock, 
  Eye, 
  Download, 
  Trash2, 
  AlertTriangle, 
  CheckCircle2,
  ExternalLink,
  FileText,
  Key
} from 'lucide-react';
import { OAuthService } from '../services/oauthService';

interface PrivacyControlsProps {
  className?: string;
}

export const PrivacyControls: React.FC<PrivacyControlsProps> = ({ className = '' }) => {
  const [showDataExport, setShowDataExport] = useState(false);
  const [showAccountDeletion, setShowAccountDeletion] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  const handleDataExport = async () => {
    setIsExporting(true);
    try {
      const blob = await OAuthService.exportUserData();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `phishnet-data-export-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setShowDataExport(false);
    } catch (error) {
      console.error('Export failed:', error);
    } finally {
      setIsExporting(false);
    }
  };

  const handleAccountDeletion = async () => {
    if (deleteConfirmText !== 'DELETE') return;
    
    setIsDeleting(true);
    try {
      await OAuthService.deleteAccount();
      // Redirect to login or home page after deletion
      window.location.href = '/login';
    } catch (error) {
      console.error('Account deletion failed:', error);
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <>
      <div className={`bg-white rounded-lg border border-gray-200 ${className}`}>
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-blue-600" />
            <div>
              <h3 className="text-lg font-semibold text-gray-900">Privacy & Security</h3>
              <p className="text-sm text-gray-600">Manage your data and privacy settings</p>
            </div>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Data Protection Notice */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <Lock className="h-5 w-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="font-medium text-blue-900">Data Protection</h4>
                <p className="text-sm text-blue-800 mt-1">
                  PhishNet uses enterprise-grade encryption to protect your data. Email analysis 
                  happens in our secure sandbox environment, and raw email content is never 
                  shared with third parties.
                </p>
                <div className="mt-2 flex gap-4 text-xs text-blue-700">
                  <span>✓ End-to-end encryption</span>
                  <span>✓ Zero-trust architecture</span>
                  <span>✓ GDPR compliant</span>
                </div>
              </div>
            </div>
          </div>

          {/* Security Features */}
          <div>
            <h4 className="font-medium text-gray-900 mb-3 flex items-center gap-2">
              <Key className="h-4 w-4" />
              Active Security Features
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-md">
                <CheckCircle2 className="h-4 w-4 text-green-600" />
                <div>
                  <p className="text-sm font-medium text-green-900">OAuth 2.0 + PKCE</p>
                  <p className="text-xs text-green-700">Secure authorization flow</p>
                </div>
              </div>
              
              <div className="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-md">
                <CheckCircle2 className="h-4 w-4 text-green-600" />
                <div>
                  <p className="text-sm font-medium text-green-900">httpOnly Cookies</p>
                  <p className="text-xs text-green-700">XSS protection enabled</p>
                </div>
              </div>
              
              <div className="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-md">
                <CheckCircle2 className="h-4 w-4 text-green-600" />
                <div>
                  <p className="text-sm font-medium text-green-900">CSRF Protection</p>
                  <p className="text-xs text-green-700">Request forgery prevention</p>
                </div>
              </div>
              
              <div className="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-md">
                <CheckCircle2 className="h-4 w-4 text-green-600" />
                <div>
                  <p className="text-sm font-medium text-green-900">Token Encryption</p>
                  <p className="text-xs text-green-700">AES-256 at rest</p>
                </div>
              </div>
            </div>
          </div>

          {/* Minimal Scopes Notice */}
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <Eye className="h-5 w-5 text-yellow-600 mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="font-medium text-yellow-900">Minimal Access Principle</h4>
                <p className="text-sm text-yellow-800 mt-1">
                  PhishNet only requests the minimum Gmail permissions required for security 
                  monitoring. We use read-only access whenever possible.
                </p>
                <div className="mt-2">
                  <details className="text-xs text-yellow-700">
                    <summary className="cursor-pointer font-medium">View requested permissions</summary>
                    <ul className="mt-2 space-y-1 ml-4">
                      <li>• gmail.readonly - Read email content for analysis</li>
                      <li>• gmail.modify - Quarantine malicious emails</li>
                      <li>• gmail.settings.basic - Set up push notifications</li>
                    </ul>
                  </details>
                </div>
              </div>
            </div>
          </div>

          {/* Privacy Actions */}
          <div>
            <h4 className="font-medium text-gray-900 mb-3">Privacy Controls</h4>
            <div className="space-y-3">
              <button
                onClick={() => setShowDataExport(true)}
                className="w-full flex items-center justify-between p-3 border border-gray-200 rounded-md hover:bg-gray-50"
              >
                <div className="flex items-center gap-3">
                  <Download className="h-4 w-4 text-blue-600" />
                  <div className="text-left">
                    <p className="text-sm font-medium text-gray-900">Export Your Data</p>
                    <p className="text-xs text-gray-600">Download all your PhishNet data</p>
                  </div>
                </div>
                <ExternalLink className="h-4 w-4 text-gray-400" />
              </button>

              <button
                onClick={() => setShowAccountDeletion(true)}
                className="w-full flex items-center justify-between p-3 border border-red-200 rounded-md hover:bg-red-50"
              >
                <div className="flex items-center gap-3">
                  <Trash2 className="h-4 w-4 text-red-600" />
                  <div className="text-left">
                    <p className="text-sm font-medium text-red-900">Delete Account</p>
                    <p className="text-xs text-red-600">Permanently remove all data</p>
                  </div>
                </div>
                <ExternalLink className="h-4 w-4 text-gray-400" />
              </button>
            </div>
          </div>

          {/* Legal Links */}
          <div className="pt-4 border-t border-gray-200">
            <div className="flex flex-wrap gap-4 text-sm">
              <a 
                href="/privacy" 
                className="text-blue-600 hover:text-blue-700 flex items-center gap-1"
              >
                <FileText className="h-3 w-3" />
                Privacy Policy
              </a>
              <a 
                href="/terms" 
                className="text-blue-600 hover:text-blue-700 flex items-center gap-1"
              >
                <FileText className="h-3 w-3" />
                Terms of Service
              </a>
              <a 
                href="/security" 
                className="text-blue-600 hover:text-blue-700 flex items-center gap-1"
              >
                <Shield className="h-3 w-3" />
                Security Policy
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Data Export Modal */}
      {showDataExport && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md mx-4">
            <div className="flex items-center gap-3 mb-4">
              <Download className="h-6 w-6 text-blue-600" />
              <h3 className="text-lg font-semibold">Export Your Data</h3>
            </div>
            
            <div className="space-y-3 text-sm text-gray-600 mb-6">
              <p>Your export will include:</p>
              <ul className="space-y-1 ml-4">
                <li>• Account information and settings</li>
                <li>• Scan history and results</li>
                <li>• Connection and audit logs</li>
                <li>• OAuth authorization details</li>
              </ul>
              <p className="text-xs text-gray-500">
                Data is exported in JSON format and does not include raw email content.
              </p>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => setShowDataExport(false)}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleDataExport}
                disabled={isExporting}
                className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {isExporting ? 'Exporting...' : 'Download'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Account Deletion Modal */}
      {showAccountDeletion && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md mx-4">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="h-6 w-6 text-red-600" />
              <h3 className="text-lg font-semibold">Delete Account</h3>
            </div>
            
            <div className="space-y-3 text-sm text-gray-600 mb-6">
              <p className="font-medium text-red-800">This action cannot be undone!</p>
              <p>Deleting your account will:</p>
              <ul className="space-y-1 ml-4">
                <li>• Permanently delete all your data</li>
                <li>• Revoke Gmail access immediately</li>
                <li>• Remove all scan history</li>
                <li>• Cancel any active monitoring</li>
              </ul>
              
              <div className="mt-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Type "DELETE" to confirm:
                </label>
                <input
                  type="text"
                  value={deleteConfirmText}
                  onChange={(e) => setDeleteConfirmText(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500"
                  placeholder="DELETE"
                />
              </div>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => {
                  setShowAccountDeletion(false);
                  setDeleteConfirmText('');
                }}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleAccountDeletion}
                disabled={isDeleting || deleteConfirmText !== 'DELETE'}
                className="flex-1 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50"
              >
                {isDeleting ? 'Deleting...' : 'Delete Account'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default PrivacyControls;