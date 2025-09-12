import React, { 
  useEffect, 
  useState, 
  useRef, 
  useMemo, 
  useCallback,
  ReactNode 
} from 'react';
import { FixedSizeList as List } from 'react-window';
import { Loader2, Mail, AlertTriangle } from 'lucide-react';

export interface EmailListItem {
  id: string;
  subject: string;
  sender: string;
  received_at: string;
  status: 'scanning' | 'safe' | 'suspicious' | 'malicious' | 'quarantined';
  confidence_score?: number;
  tenant_id: string;
  has_attachments: boolean;
  preview?: string;
}

export interface VirtualEmailListProps {
  emails: EmailListItem[];
  itemHeight?: number;
  height?: number;
  width?: string | number;
  onEmailSelect?: (email: EmailListItem) => void;
  onEmailsLoad?: (startIndex: number, endIndex: number) => void;
  selectedEmailIds?: Set<string>;
  onEmailToggle?: (emailId: string) => void;
  renderEmail?: (email: EmailListItem, index: number, isSelected: boolean) => ReactNode;
  loading?: boolean;
  error?: string;
  className?: string;
  hasNextPage?: boolean;
  isLoadingNextPage?: boolean;
  loadNextPage?: () => void;
}

interface EmailItemProps {
  index: number;
  style: React.CSSProperties;
  data: {
    emails: EmailListItem[];
    onEmailSelect?: (email: EmailListItem) => void;
    selectedEmailIds?: Set<string>;
    onEmailToggle?: (emailId: string) => void;
    renderEmail?: (email: EmailListItem, index: number, isSelected: boolean) => ReactNode;
  };
}

const EmailItem: React.FC<EmailItemProps> = ({ index, style, data }) => {
  const { emails, onEmailSelect, selectedEmailIds, onEmailToggle, renderEmail } = data;
  const email = emails[index];
  const isSelected = selectedEmailIds?.has(email.id) || false;

  if (!email) {
    return (
      <div style={style} className="flex items-center justify-center p-4">
        <Loader2 className="h-4 w-4 animate-spin text-gray-400" />
      </div>
    );
  }

  if (renderEmail) {
    return <div style={style}>{renderEmail(email, index, isSelected)}</div>;
  }

  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'safe': return 'text-green-400 bg-green-900/20';
      case 'suspicious': return 'text-yellow-400 bg-yellow-900/20';
      case 'malicious': return 'text-red-400 bg-red-900/20';
      case 'quarantined': return 'text-orange-400 bg-orange-900/20';
      case 'scanning': return 'text-blue-400 bg-blue-900/20';
      default: return 'text-gray-400 bg-gray-900/20';
    }
  };

  const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);

    if (diffDays === 0) {
      if (diffHours === 0) {
        const diffMinutes = Math.floor(diffMs / (1000 * 60));
        return diffMinutes < 1 ? 'Just now' : `${diffMinutes}m ago`;
      }
      return `${diffHours}h ago`;
    } else if (diffDays < 7) {
      return `${diffDays}d ago`;
    } else {
      return date.toLocaleDateString();
    }
  };

  return (
    <div 
      style={style} 
      className={`
        flex items-center p-4 border-b border-gray-700 hover:bg-gray-800/50 cursor-pointer transition-colors
        ${isSelected ? 'bg-blue-900/30 border-blue-600' : ''}
      `}
      onClick={() => onEmailSelect?.(email)}
    >
      {/* Selection checkbox */}
      {onEmailToggle && (
        <div className="mr-3 flex-shrink-0">
          <input
            type="checkbox"
            checked={isSelected}
            onChange={(e) => {
              e.stopPropagation();
              onEmailToggle(email.id);
            }}
            className="h-4 w-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2"
          />
        </div>
      )}

      {/* Email icon */}
      <div className="mr-3 flex-shrink-0">
        <Mail className="h-5 w-5 text-gray-400" />
        {email.has_attachments && (
          <div className="absolute -mt-1 -ml-1">
            <div className="h-2 w-2 bg-blue-400 rounded-full"></div>
          </div>
        )}
      </div>

      {/* Email content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center space-x-2">
            <span className="text-white font-medium truncate max-w-xs">
              {email.sender}
            </span>
            <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(email.status)}`}>
              {email.status}
            </span>
            {email.confidence_score !== undefined && (
              <span className="text-xs text-gray-400">
                {Math.round(email.confidence_score * 100)}%
              </span>
            )}
          </div>
          <span className="text-xs text-gray-400 flex-shrink-0">
            {formatDate(email.received_at)}
          </span>
        </div>
        
        <div className="text-sm text-gray-300 truncate mb-1">
          {email.subject}
        </div>
        
        {email.preview && (
          <div className="text-xs text-gray-400 truncate">
            {email.preview}
          </div>
        )}
      </div>

      {/* Status indicator */}
      <div className="ml-3 flex-shrink-0">
        {email.status === 'scanning' && (
          <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
        )}
        {(email.status === 'suspicious' || email.status === 'malicious') && (
          <AlertTriangle className="h-4 w-4 text-yellow-400" />
        )}
      </div>
    </div>
  );
};

export const VirtualEmailList: React.FC<VirtualEmailListProps> = ({
  emails,
  itemHeight = 100,
  height = 600,
  width = '100%',
  onEmailSelect,
  onEmailsLoad,
  selectedEmailIds,
  onEmailToggle,
  renderEmail,
  loading = false,
  error,
  className = '',
  hasNextPage = false,
  isLoadingNextPage = false,
  loadNextPage,
}) => {
  const listRef = useRef<List>(null);
  const [visibleRange, setVisibleRange] = useState({ start: 0, end: 0 });

  const itemData = useMemo(() => ({
    emails,
    onEmailSelect,
    selectedEmailIds,
    onEmailToggle,
    renderEmail,
  }), [emails, onEmailSelect, selectedEmailIds, onEmailToggle, renderEmail]);

  const handleItemsRendered = useCallback(({
    visibleStartIndex,
    visibleStopIndex
  }: {
    visibleStartIndex: number;
    visibleStopIndex: number;
  }) => {
    setVisibleRange({ start: visibleStartIndex, end: visibleStopIndex });
    onEmailsLoad?.(visibleStartIndex, visibleStopIndex);

    // Load next page when near the end
    if (
      hasNextPage && 
      !isLoadingNextPage && 
      loadNextPage && 
      visibleStopIndex >= emails.length - 5
    ) {
      loadNextPage();
    }
  }, [onEmailsLoad, hasNextPage, isLoadingNextPage, loadNextPage, emails.length]);

  const scrollToEmail = useCallback((emailId: string) => {
    const index = emails.findIndex(email => email.id === emailId);
    if (index !== -1 && listRef.current) {
      listRef.current.scrollToItem(index, 'center');
    }
  }, [emails]);

  const scrollToTop = useCallback(() => {
    if (listRef.current) {
      listRef.current.scrollTo(0);
    }
  }, []);

  // Expose scroll methods
  React.useImperativeHandle(listRef, () => ({
    scrollToEmail,
    scrollToTop,
    scrollToItem: (index: number, align?: 'auto' | 'smart' | 'center' | 'end' | 'start') => {
      listRef.current?.scrollToItem(index, align);
    }
  }));

  if (error) {
    return (
      <div className={`flex items-center justify-center p-8 text-red-400 ${className}`}>
        <AlertTriangle className="h-6 w-6 mr-2" />
        <span>Error loading emails: {error}</span>
      </div>
    );
  }

  if (loading && emails.length === 0) {
    return (
      <div className={`flex items-center justify-center p-8 ${className}`}>
        <Loader2 className="h-6 w-6 animate-spin text-blue-400 mr-2" />
        <span className="text-gray-400">Loading emails...</span>
      </div>
    );
  }

  if (emails.length === 0) {
    return (
      <div className={`flex items-center justify-center p-8 text-gray-400 ${className}`}>
        <Mail className="h-6 w-6 mr-2" />
        <span>No emails found</span>
      </div>
    );
  }

  // Add loading indicator at the end for infinite scroll
  const itemCount = hasNextPage ? emails.length + 1 : emails.length;

  return (
    <div className={`${className}`}>
      <List
        ref={listRef}
        height={height}
        itemCount={itemCount}
        itemSize={itemHeight}
        itemData={itemData}
        onItemsRendered={handleItemsRendered}
        width={width}
        className="bg-gray-900 border border-gray-700 rounded-lg"
      >
        {({ index, style }) => {
          // Show loading indicator for the last item when loading next page
          if (index >= emails.length) {
            return (
              <div style={style} className="flex items-center justify-center p-4">
                <Loader2 className="h-4 w-4 animate-spin text-blue-400 mr-2" />
                <span className="text-gray-400">Loading more emails...</span>
              </div>
            );
          }
          
          return <EmailItem index={index} style={style} data={itemData} />;
        }}
      </List>
      
      {/* Performance stats */}
      <div className="mt-2 text-xs text-gray-500 flex justify-between">
        <span>
          Showing {visibleRange.start + 1}-{Math.min(visibleRange.end + 1, emails.length)} of {emails.length} emails
        </span>
        {hasNextPage && (
          <span>
            {isLoadingNextPage ? 'Loading...' : 'Scroll for more'}
          </span>
        )}
      </div>
    </div>
  );
};

export default VirtualEmailList;
