import React, { useState } from 'react';
import { 
  Shield, 
  Archive, 
  RotateCcw, 
  CheckCircle,
  XCircle,
  AlertTriangle,
  Lock,
  Unlock,
  User,
  Clock,
  MessageSquare,
  ChevronDown,
  Loader2
} from 'lucide-react';
import { usePermissions } from '../hooks/useAuth';
import { apiService } from '../services/apiService';

export interface EmailActionPermissions {
  canQuarantine: boolean;
  canRestore: boolean;
  canWhitelist: boolean;
  canDelete: boolean;
  canViewDetails: boolean;
  canBulkAction: boolean;
}

interface EmailActionsProps {
  emailId: number;
  currentStatus: 'safe' | 'suspicious' | 'malicious' | 'quarantined' | 'scanning' | 'pending';
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  sender?: string;
  subject?: string;
  onActionComplete?: (action: string, success: boolean, message?: string) => void;
  compact?: boolean;
  disabled?: boolean;
}

interface ActionConfirmationModalProps {
  isOpen: boolean;
  action: {
    type: 'quarantine' | 'restore' | 'whitelist' | 'delete';
    label: string;
    description: string;
    icon: React.ReactNode;
    color: string;
  };
  emailId: number;
  emailSubject?: string;
  onConfirm: (reason?: string) => Promise<void>;
  onCancel: () => void;
  requireReason?: boolean;
  warningMessage?: string;
}

const ActionConfirmationModal: React.FC<ActionConfirmationModalProps> = ({
  isOpen,
  action,
  emailId,
  emailSubject,
  onConfirm,
  onCancel,
  requireReason = false,
  warningMessage
}) => {
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleConfirm = async () => {
    if (requireReason && !reason.trim()) {
      return;
    }
    
    setLoading(true);
    try {
      await onConfirm(reason || undefined);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg max-w-md w-full mx-4">
        <div className="p-6">
          {/* Header */}
          <div className="flex items-center space-x-3 mb-4">
            <div className={action.color}>
              {action.icon}
            </div>
            <h3 className="text-lg font-semibold text-gray-900">
              {action.label}
            </h3>
          </div>

          {/* Description */}
          <p className="text-gray-600 mb-4">
            {action.description}
          </p>

          {/* Email info */}
          <div className="bg-gray-50 rounded p-3 mb-4">
            <div className="text-sm">
              <div className="font-medium text-gray-700">Email ID: {emailId}</div>
              {emailSubject && (
                <div className="text-gray-600 mt-1 truncate">
                  Subject: {emailSubject}
                </div>
              )}
            </div>
          </div>

          {/* Warning message */}
          {warningMessage && (
            <div className="bg-yellow-50 border border-yellow-200 rounded p-3 mb-4">
              <div className="flex items-start space-x-2">
                <AlertTriangle className="h-5 w-5 text-yellow-600 flex-shrink-0 mt-0.5" />
                <div className="text-sm text-yellow-800">
                  {warningMessage}
                </div>
              </div>
            </div>
          )}

          {/* Reason input */}
          {requireReason && (
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Reason <span className="text-red-500">*</span>
              </label>
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Please provide a reason for this action..."
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                rows={3}
                required
              />
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end space-x-3">
            <button
              onClick={onCancel}
              disabled={loading}
              className="px-4 py-2 text-sm text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              onClick={handleConfirm}
              disabled={loading || (requireReason && !reason.trim())}
              className={`px-4 py-2 text-sm text-white rounded-md transition-colors disabled:opacity-50 flex items-center space-x-2 ${action.color.replace('text-', 'bg-').replace('-600', '-600 hover:bg-').replace('-500', '-700')}`}
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              <span>{loading ? 'Processing...' : action.label}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export const EmailActions: React.FC<EmailActionsProps> = ({
  emailId,
  currentStatus,
  riskLevel,
  sender,
  subject,
  onActionComplete,
  compact = false,
  disabled = false
}) => {
  const permissions = usePermissions();
  const [confirmationModal, setConfirmationModal] = useState<{
    isOpen: boolean;
    action?: any;
  }>({ isOpen: false });
  const [loading, setLoading] = useState<string | null>(null);

  // Define available actions based on current status and permissions
  const getAvailableActions = () => {
    const actions = [];

    // Quarantine action
    if (['safe', 'suspicious', 'malicious'].includes(currentStatus) && 
        permissions.canQuarantine()) {
      actions.push({
        type: 'quarantine',
        label: 'Quarantine',
        description: 'Move this email to quarantine to prevent delivery and access.',
        icon: <Shield className="h-5 w-5" />,
        color: 'text-red-600',
        requireReason: true,
        warningMessage: riskLevel === 'low' ? 'This email has a low risk score. Are you sure you want to quarantine it?' : undefined
      });
    }

    // Restore action
    if (currentStatus === 'quarantined' && permissions.canQuarantine()) {
      actions.push({
        type: 'restore',
        label: 'Restore',
        description: 'Remove this email from quarantine and restore normal access.',
        icon: <RotateCcw className="h-5 w-5" />,
        color: 'text-blue-600',
        requireReason: true
      });
    }

    // Whitelist action (admin only)
    if (['suspicious', 'malicious', 'quarantined'].includes(currentStatus) && 
        permissions.canWhitelist()) {
      actions.push({
        type: 'whitelist',
        label: 'Whitelist',
        description: 'Add sender to whitelist and mark as safe. Future emails from this sender will be trusted.',
        icon: <CheckCircle className="h-5 w-5" />,
        color: 'text-green-600',
        requireReason: true,
        warningMessage: 'This will whitelist the sender for all future emails. This action should only be performed after thorough verification.'
      });
    }

    // Delete action (admin/analyst only)
    if (permissions.canDeleteEmails() && currentStatus !== 'scanning') {
      actions.push({
        type: 'delete',
        label: 'Delete',
        description: 'Permanently delete this email. This action cannot be undone.',
        icon: <XCircle className="h-5 w-5" />,
        color: 'text-red-600',
        requireReason: true,
        warningMessage: 'This action is permanent and cannot be undone. The email will be completely removed from the system.'
      });
    }

    return actions;
  };

  const handleActionClick = (action: any) => {
    setConfirmationModal({
      isOpen: true,
      action
    });
  };

  const executeAction = async (actionType: string, reason?: string) => {
    setLoading(actionType);
    
    try {
      let result;
      
      switch (actionType) {
        case 'quarantine':
          result = await apiService.updateEmailStatus(emailId, 'quarantined', reason);
          break;
        case 'restore':
          result = await apiService.updateEmailStatus(emailId, 'safe', reason);
          break;
        case 'whitelist':
          // This would typically call a separate whitelist endpoint
          result = await apiService.updateEmailStatus(emailId, 'safe', reason);
          // Also add to whitelist
          // await apiService.addToWhitelist(sender, reason);
          break;
        case 'delete':
          await apiService.deleteEmail(emailId);
          result = { success: true };
          break;
        default:
          throw new Error(`Unknown action: ${actionType}`);
      }

      setConfirmationModal({ isOpen: false });
      
      onActionComplete?.(actionType, true, `Email ${actionType}d successfully`);
      
    } catch (error: any) {
      console.error(`Failed to ${actionType} email:`, error);
      onActionComplete?.(actionType, false, error.message || `Failed to ${actionType} email`);
    } finally {
      setLoading(null);
    }
  };

  const availableActions = getAvailableActions();

  if (availableActions.length === 0) {
    return null;
  }

  if (compact) {
    return (
      <div className="flex space-x-1">
        {availableActions.slice(0, 2).map((action) => (
          <button
            key={action.type}
            onClick={() => handleActionClick(action)}
            disabled={disabled || loading === action.type}
            className={`p-1 rounded hover:bg-gray-100 transition-colors disabled:opacity-50 ${action.color}`}
            title={action.label}
          >
            {loading === action.type ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              React.cloneElement(action.icon, { className: 'h-4 w-4' })
            )}
          </button>
        ))}
        
        {availableActions.length > 2 && (
          <div className="relative group">
            <button className="p-1 rounded hover:bg-gray-100 transition-colors">
              <ChevronDown className="h-4 w-4 text-gray-500" />
            </button>
            <div className="absolute right-0 top-8 bg-white border rounded shadow-lg py-1 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
              {availableActions.slice(2).map((action) => (
                <button
                  key={action.type}
                  onClick={() => handleActionClick(action)}
                  disabled={disabled || loading === action.type}
                  className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-100 disabled:opacity-50"
                >
                  <div className="flex items-center space-x-2">
                    <div className={action.color}>
                      {React.cloneElement(action.icon, { className: 'h-4 w-4' })}
                    </div>
                    <span>{action.label}</span>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <>
      <div className="space-y-2">
        <h4 className="text-sm font-medium text-gray-700 mb-3">Available Actions</h4>
        
        {availableActions.map((action) => (
          <button
            key={action.type}
            onClick={() => handleActionClick(action)}
            disabled={disabled || loading === action.type || currentStatus === 'scanning'}
            className={`w-full flex items-center space-x-3 p-3 border rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
              loading === action.type ? 'bg-gray-50' : ''
            }`}
          >
            <div className={action.color}>
              {loading === action.type ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                action.icon
              )}
            </div>
            
            <div className="flex-1 text-left">
              <div className="font-medium text-gray-900">{action.label}</div>
              <div className="text-sm text-gray-600">{action.description}</div>
            </div>
            
            {action.requireReason && (
              <MessageSquare className="h-4 w-4 text-gray-400" />
            )}
          </button>
        ))}

        {/* Status info */}
        <div className="mt-4 p-3 bg-gray-50 rounded-lg">
          <div className="text-sm">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-600">Current Status:</span>
              <span className={`font-medium capitalize ${
                currentStatus === 'safe' ? 'text-green-600' :
                currentStatus === 'suspicious' ? 'text-yellow-600' :
                currentStatus === 'malicious' ? 'text-red-600' :
                currentStatus === 'quarantined' ? 'text-purple-600' :
                'text-gray-600'
              }`}>
                {currentStatus}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-gray-600">Risk Level:</span>
              <span className={`font-medium capitalize ${
                riskLevel === 'critical' ? 'text-red-600' :
                riskLevel === 'high' ? 'text-orange-600' :
                riskLevel === 'medium' ? 'text-yellow-600' :
                'text-green-600'
              }`}>
                {riskLevel}
              </span>
            </div>
          </div>
        </div>

        {/* Permission info */}
        <div className="mt-2 text-xs text-gray-500">
          <div className="flex items-center space-x-1">
            {permissions.isAdmin() ? (
              <>
                <Lock className="h-3 w-3" />
                <span>Admin permissions</span>
              </>
            ) : permissions.isAnalyst() ? (
              <>
                <User className="h-3 w-3" />
                <span>Analyst permissions</span>
              </>
            ) : (
              <>
                <Unlock className="h-3 w-3" />
                <span>Limited permissions</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Confirmation Modal */}
      <ActionConfirmationModal
        isOpen={confirmationModal.isOpen}
        action={confirmationModal.action}
        emailId={emailId}
        emailSubject={subject}
        onConfirm={(reason) => executeAction(confirmationModal.action?.type, reason)}
        onCancel={() => setConfirmationModal({ isOpen: false })}
        requireReason={confirmationModal.action?.requireReason}
        warningMessage={confirmationModal.action?.warningMessage}
      />
    </>
  );
};

// Bulk actions component for multiple emails
interface BulkEmailActionsProps {
  selectedEmailIds: number[];
  onActionComplete?: (action: string, success: boolean, message?: string) => void;
  onClearSelection?: () => void;
}

export const BulkEmailActions: React.FC<BulkEmailActionsProps> = ({
  selectedEmailIds,
  onActionComplete,
  onClearSelection
}) => {
  const permissions = usePermissions();
  const [loading, setLoading] = useState<string | null>(null);
  const [confirmationModal, setConfirmationModal] = useState<{
    isOpen: boolean;
    action?: any;
  }>({ isOpen: false });

  if (selectedEmailIds.length === 0 || !permissions.canBulkAction) {
    return null;
  }

  const bulkActions = [
    {
      type: 'bulk_quarantine',
      label: `Quarantine ${selectedEmailIds.length} emails`,
      description: 'Move all selected emails to quarantine.',
      icon: <Shield className="h-5 w-5" />,
      color: 'text-red-600',
      requireReason: true
    },
    {
      type: 'bulk_restore',
      label: `Restore ${selectedEmailIds.length} emails`,
      description: 'Restore all selected emails from quarantine.',
      icon: <RotateCcw className="h-5 w-5" />,
      color: 'text-blue-600',
      requireReason: true
    }
  ];

  const executeBulkAction = async (actionType: string, reason?: string) => {
    setLoading(actionType);
    
    try {
      const action = actionType.replace('bulk_', '');
      await apiService.bulkUpdateEmails(selectedEmailIds, action, reason);
      
      setConfirmationModal({ isOpen: false });
      onActionComplete?.(actionType, true, `Successfully ${action}d ${selectedEmailIds.length} emails`);
      onClearSelection?.();
      
    } catch (error: any) {
      console.error(`Failed to ${actionType}:`, error);
      onActionComplete?.(actionType, false, error.message || `Failed to ${actionType}`);
    } finally {
      setLoading(null);
    }
  };

  return (
    <>
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <CheckCircle className="h-5 w-5 text-blue-600" />
            <span className="font-medium text-blue-900">
              {selectedEmailIds.length} emails selected
            </span>
          </div>
          
          <button
            onClick={onClearSelection}
            className="text-sm text-blue-600 hover:text-blue-800"
          >
            Clear selection
          </button>
        </div>

        <div className="flex flex-wrap gap-2">
          {bulkActions.map((action) => (
            <button
              key={action.type}
              onClick={() => setConfirmationModal({ isOpen: true, action })}
              disabled={loading === action.type}
              className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-colors disabled:opacity-50 ${
                loading === action.type ? 'bg-gray-100' : 'bg-white hover:bg-gray-50'
              } border`}
            >
              <div className={action.color}>
                {loading === action.type ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  React.cloneElement(action.icon, { className: 'h-4 w-4' })
                )}
              </div>
              <span>{action.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Bulk Action Confirmation Modal */}
      {confirmationModal.action && (
        <ActionConfirmationModal
          isOpen={confirmationModal.isOpen}
          action={{
            ...confirmationModal.action,
            description: `${confirmationModal.action.description} This will affect ${selectedEmailIds.length} emails.`
          }}
          emailId={0} // Not applicable for bulk actions
          onConfirm={(reason) => executeBulkAction(confirmationModal.action?.type, reason)}
          onCancel={() => setConfirmationModal({ isOpen: false })}
          requireReason={confirmationModal.action?.requireReason}
          warningMessage={`This action will be applied to ${selectedEmailIds.length} emails. Please ensure this is intended.`}
        />
      )}
    </>
  );
};
