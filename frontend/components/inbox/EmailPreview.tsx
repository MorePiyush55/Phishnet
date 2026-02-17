import React, { useEffect, useState } from 'react';
import { ArrowLeft, Reply, ReplyAll, Forward, MoreVertical, Star, Archive, Trash2, AlertTriangle, Shield, Download } from 'lucide-react';
import DOMPurify from 'dompurify';

/**
 * EmailPreview Component
 * 
 * Displays full email content with threat analysis, sanitized HTML rendering,
 * and action buttons (Reply, Forward, etc.)
 */

// ==================== Types ====================

interface EmailParticipant {
    name?: string;
    email: string;
}

interface EmailRecipients {
    to: EmailParticipant[];
    cc: EmailParticipant[];
    bcc: EmailParticipant[];
}

interface EmailAttachment {
    attachment_id: string;
    filename: string;
    size_bytes: number;
    mime_type: string;
    download_url?: string;
}

interface Email {
    message_id: string;
    thread_id: string;
    sender: EmailParticipant;
    recipients: EmailRecipients;
    subject: string;
    body_text?: string;
    body_html?: string;
    is_read: boolean;
    is_starred: boolean;
    has_attachment: boolean;
    attachments: EmailAttachment[];
    threat_score: number;
    risk_level: 'SAFE' | 'SUSPICIOUS' | 'PHISHING';
    threat_indicators: string[];
    received_at: string;
    timestamp: string;
}

interface EmailPreviewProps {
    email: Email | null;
    onClose?: () => void;
    onReply?: (email: Email) => void;
    onReplyAll?: (email: Email) => void;
    onForward?: (email: Email) => void;
    onStarToggle?: (messageId: string, starred: boolean) => void;
    onArchive?: (messageId: string) => void;
    onDelete?: (messageId: string) => void;
    onMarkRead?: (messageId: string, read: boolean) => void;
    autoMarkReadDelay?: number; // Delay in ms before auto-marking as read
}

// ==================== Helper Functions ====================

const formatDate = (timestamp: string): string => {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
};

const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const getThreatBannerColor = (riskLevel: string): string => {
    switch (riskLevel) {
        case 'PHISHING':
            return 'bg-red-50 border-red-200 text-red-900';
        case 'SUSPICIOUS':
            return 'bg-yellow-50 border-yellow-200 text-yellow-900';
        case 'SAFE':
        default:
            return 'bg-green-50 border-green-200 text-green-900';
    }
};

const getThreatIcon = (riskLevel: string) => {
    switch (riskLevel) {
        case 'PHISHING':
            return <AlertTriangle className="w-5 h-5 text-red-600" />;
        case 'SUSPICIOUS':
            return <AlertTriangle className="w-5 h-5 text-yellow-600" />;
        case 'SAFE':
        default:
            return <Shield className="w-5 h-5 text-green-600" />;
    }
};

const sanitizeHTML = (html: string): string => {
    return DOMPurify.sanitize(html, {
        ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'a', 'blockquote', 'pre', 'code', 'div', 'span', 'table', 'thead', 'tbody', 'tr', 'th', 'td'],
        ALLOWED_ATTR: ['href', 'target', 'rel', 'class', 'style'],
        ALLOW_DATA_ATTR: false,
    });
};

// ==================== Main Component ====================

export const EmailPreview: React.FC<EmailPreviewProps> = ({
    email,
    onClose,
    onReply,
    onReplyAll,
    onForward,
    onStarToggle,
    onArchive,
    onDelete,
    onMarkRead,
    autoMarkReadDelay = 2000,
}) => {
    const [showFullHeaders, setShowFullHeaders] = useState(false);
    const [loadExternalImages, setLoadExternalImages] = useState(false);

    // Auto-mark as read after delay
    useEffect(() => {
        if (!email || email.is_read || !onMarkRead) return;

        const timer = setTimeout(() => {
            onMarkRead(email.message_id, true);
        }, autoMarkReadDelay);

        return () => clearTimeout(timer);
    }, [email, autoMarkReadDelay, onMarkRead]);

    if (!email) {
        return (
            <div className="flex flex-col items-center justify-center h-full bg-gray-50 text-gray-500">
                <svg className="w-24 h-24 mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
                <p className="text-lg font-medium">No email selected</p>
                <p className="text-sm">Select an email from the list to view its contents</p>
            </div>
        );
    }

    const handleStarClick = () => {
        if (onStarToggle) {
            onStarToggle(email.message_id, !email.is_starred);
        }
    };

    const handleArchiveClick = () => {
        if (onArchive) {
            onArchive(email.message_id);
        }
    };

    const handleDeleteClick = () => {
        if (onDelete) {
            onDelete(email.message_id);
        }
    };

    const handleReplyClick = () => {
        if (onReply) {
            onReply(email);
        }
    };

    const handleReplyAllClick = () => {
        if (onReplyAll) {
            onReplyAll(email);
        }
    };

    const handleForwardClick = () => {
        if (onForward) {
            onForward(email);
        }
    };

    return (
        <div className="flex flex-col h-full bg-white">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                {/* Back Button (Mobile) */}
                {onClose && (
                    <button
                        onClick={onClose}
                        className="mr-4 p-2 rounded-lg hover:bg-gray-100 lg:hidden"
                        aria-label="Back to list"
                    >
                        <ArrowLeft className="w-5 h-5" />
                    </button>
                )}

                {/* Action Buttons */}
                <div className="flex items-center gap-2">
                    <button
                        onClick={handleStarClick}
                        className={`p-2 rounded-lg hover:bg-gray-100 transition-colors ${email.is_starred ? 'text-yellow-500' : 'text-gray-600'
                            }`}
                        aria-label={email.is_starred ? 'Unstar' : 'Star'}
                    >
                        <Star className="w-5 h-5" fill={email.is_starred ? 'currentColor' : 'none'} />
                    </button>

                    <button
                        onClick={handleArchiveClick}
                        className="p-2 rounded-lg hover:bg-gray-100 text-gray-600"
                        title="Archive"
                    >
                        <Archive className="w-5 h-5" />
                    </button>

                    <button
                        onClick={handleDeleteClick}
                        className="p-2 rounded-lg hover:bg-gray-100 text-gray-600"
                        title="Delete"
                    >
                        <Trash2 className="w-5 h-5" />
                    </button>

                    <button className="p-2 rounded-lg hover:bg-gray-100 text-gray-600" title="More actions">
                        <MoreVertical className="w-5 h-5" />
                    </button>
                </div>
            </div>

            {/* Email Content */}
            <div className="flex-1 overflow-y-auto">
                <div className="max-w-4xl mx-auto px-6 py-6">
                    {/* Subject */}
                    <h1 className="text-2xl font-semibold text-gray-900 mb-4">
                        {email.subject || '(No subject)'}
                    </h1>

                    {/* Threat Analysis Banner */}
                    {email.risk_level !== 'SAFE' && (
                        <div className={`mb-6 p-4 rounded-lg border-2 ${getThreatBannerColor(email.risk_level)}`}>
                            <div className="flex items-start gap-3">
                                {getThreatIcon(email.risk_level)}
                                <div className="flex-1">
                                    <h3 className="font-semibold mb-1">
                                        {email.risk_level === 'PHISHING' ? 'Phishing Detected' : 'Suspicious Email'}
                                    </h3>
                                    <p className="text-sm mb-2">
                                        Threat Score: <span className="font-mono font-semibold">{(email.threat_score * 100).toFixed(1)}%</span>
                                    </p>
                                    {email.threat_indicators.length > 0 && (
                                        <div className="mt-2">
                                            <p className="text-sm font-medium mb-1">Threat Indicators:</p>
                                            <ul className="text-sm list-disc list-inside space-y-1">
                                                {email.threat_indicators.map((indicator, idx) => (
                                                    <li key={idx}>{indicator}</li>
                                                ))}
                                            </ul>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Email Header */}
                    <div className="mb-6 pb-6 border-b border-gray-200">
                        {/* Sender */}
                        <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-full bg-blue-500 flex items-center justify-center text-white font-semibold">
                                    {(email.sender.name || email.sender.email).charAt(0).toUpperCase()}
                                </div>
                                <div>
                                    <div className="font-semibold text-gray-900">
                                        {email.sender.name || email.sender.email}
                                    </div>
                                    <div className="text-sm text-gray-600">
                                        &lt;{email.sender.email}&gt;
                                    </div>
                                </div>
                            </div>
                            <div className="text-sm text-gray-600">
                                {formatDate(email.received_at)}
                            </div>
                        </div>

                        {/* Recipients */}
                        <div className="text-sm text-gray-600">
                            <div className="flex items-start gap-2">
                                <span className="font-medium">To:</span>
                                <span>
                                    {email.recipients.to.map(r => r.name || r.email).join(', ')}
                                </span>
                            </div>

                            {email.recipients.cc.length > 0 && (
                                <div className="flex items-start gap-2 mt-1">
                                    <span className="font-medium">Cc:</span>
                                    <span>
                                        {email.recipients.cc.map(r => r.name || r.email).join(', ')}
                                    </span>
                                </div>
                            )}

                            {showFullHeaders && email.recipients.bcc.length > 0 && (
                                <div className="flex items-start gap-2 mt-1">
                                    <span className="font-medium">Bcc:</span>
                                    <span>
                                        {email.recipients.bcc.map(r => r.name || r.email).join(', ')}
                                    </span>
                                </div>
                            )}

                            <button
                                onClick={() => setShowFullHeaders(!showFullHeaders)}
                                className="text-blue-600 hover:text-blue-700 text-xs mt-2"
                            >
                                {showFullHeaders ? 'Hide details' : 'Show details'}
                            </button>
                        </div>
                    </div>

                    {/* Attachments */}
                    {email.has_attachment && email.attachments.length > 0 && (
                        <div className="mb-6">
                            <h3 className="text-sm font-semibold text-gray-700 mb-2">
                                Attachments ({email.attachments.length})
                            </h3>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                {email.attachments.map((attachment) => (
                                    <div
                                        key={attachment.attachment_id}
                                        className="flex items-center gap-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50"
                                    >
                                        <div className="flex-shrink-0">
                                            <div className="w-10 h-10 bg-gray-100 rounded flex items-center justify-center">
                                                <svg className="w-6 h-6 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                                                </svg>
                                            </div>
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="text-sm font-medium text-gray-900 truncate">
                                                {attachment.filename}
                                            </div>
                                            <div className="text-xs text-gray-500">
                                                {formatFileSize(attachment.size_bytes)}
                                            </div>
                                        </div>
                                        <a
                                            href={attachment.download_url || `#`}
                                            download={attachment.filename}
                                            className="flex-shrink-0 p-2 text-blue-600 hover:bg-blue-50 rounded"
                                            title="Download"
                                        >
                                            <Download className="w-4 h-4" />
                                        </a>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Email Body */}
                    <div className="prose max-w-none">
                        {email.body_html ? (
                            <div
                                dangerouslySetInnerHTML={{
                                    __html: sanitizeHTML(email.body_html),
                                }}
                                className="email-body"
                            />
                        ) : (
                            <pre className="whitespace-pre-wrap font-sans text-gray-900">
                                {email.body_text}
                            </pre>
                        )}
                    </div>
                </div>
            </div>

            {/* Action Bar */}
            <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 bg-gray-50">
                <div className="flex items-center gap-2">
                    <button
                        onClick={handleReplyClick}
                        className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                    >
                        <Reply className="w-4 h-4" />
                        Reply
                    </button>

                    <button
                        onClick={handleReplyAllClick}
                        className="inline-flex items-center gap-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-100 transition-colors"
                    >
                        <ReplyAll className="w-4 h-4" />
                        Reply All
                    </button>

                    <button
                        onClick={handleForwardClick}
                        className="inline-flex items-center gap-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-100 transition-colors"
                    >
                        <Forward className="w-4 h-4" />
                        Forward
                    </button>
                </div>
            </div>
        </div>
    );
};

export default EmailPreview;
