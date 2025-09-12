import { create } from 'zustand';
import { devtools } from 'zustand/middleware';

export interface FilterState {
  searchTerm: string;
  selectedRiskLevel: 'all' | 'critical' | 'high' | 'medium' | 'low';
  timeRange: '1h' | '24h' | '7d' | '30d';
  statusFilter: 'all' | 'quarantined' | 'analyzing' | 'safe';
  sortBy: 'timestamp' | 'risk_score' | 'sender';
  sortOrder: 'asc' | 'desc';
}

export interface UIState {
  // Filters
  filters: FilterState;
  filterOpen: boolean;
  
  // Modals and panels
  selectedEmailId: number | null;
  showEmailDetail: boolean;
  showLinkAnalysis: boolean;
  showAuditPanel: boolean;
  
  // WebSocket status
  wsConnected: boolean;
  wsReconnecting: boolean;
  wsLastMessage: any;
  
  // Notifications
  notifications: Array<{
    id: string;
    type: 'success' | 'error' | 'warning' | 'info';
    message: string;
    timestamp: Date;
    autoHide?: boolean;
  }>;
  
  // Loading states
  isRefreshing: boolean;
  
  // Actions
  setFilter: (key: keyof FilterState, value: any) => void;
  resetFilters: () => void;
  setFilterOpen: (open: boolean) => void;
  
  setSelectedEmailId: (id: number | null) => void;
  setShowEmailDetail: (show: boolean) => void;
  setShowLinkAnalysis: (show: boolean) => void;
  setShowAuditPanel: (show: boolean) => void;
  
  setWSConnected: (connected: boolean) => void;
  setWSReconnecting: (reconnecting: boolean) => void;
  setWSLastMessage: (message: any) => void;
  
  addNotification: (notification: Omit<UIState['notifications'][0], 'id' | 'timestamp'>) => void;
  removeNotification: (id: string) => void;
  clearNotifications: () => void;
  
  setIsRefreshing: (refreshing: boolean) => void;
}

const defaultFilters: FilterState = {
  searchTerm: '',
  selectedRiskLevel: 'all',
  timeRange: '24h',
  statusFilter: 'all',
  sortBy: 'timestamp',
  sortOrder: 'desc'
};

export const useUIStore = create<UIState>()(
  devtools(
    (set, get) => ({
      // Initial state
      filters: defaultFilters,
      filterOpen: false,
      
      selectedEmailId: null,
      showEmailDetail: false,
      showLinkAnalysis: false,
      showAuditPanel: false,
      
      wsConnected: false,
      wsReconnecting: false,
      wsLastMessage: null,
      
      notifications: [],
      
      isRefreshing: false,
      
      // Actions
      setFilter: (key, value) => 
        set((state) => ({
          filters: { ...state.filters, [key]: value }
        }), false, `setFilter:${key}`),
      
      resetFilters: () => 
        set({ filters: defaultFilters }, false, 'resetFilters'),
      
      setFilterOpen: (open) => 
        set({ filterOpen: open }, false, 'setFilterOpen'),
      
      setSelectedEmailId: (id) => 
        set({ 
          selectedEmailId: id,
          showEmailDetail: id !== null 
        }, false, 'setSelectedEmailId'),
      
      setShowEmailDetail: (show) => 
        set({ showEmailDetail: show }, false, 'setShowEmailDetail'),
      
      setShowLinkAnalysis: (show) => 
        set({ showLinkAnalysis: show }, false, 'setShowLinkAnalysis'),
      
      setShowAuditPanel: (show) => 
        set({ showAuditPanel: show }, false, 'setShowAuditPanel'),
      
      setWSConnected: (connected) => 
        set({ wsConnected: connected }, false, 'setWSConnected'),
      
      setWSReconnecting: (reconnecting) => 
        set({ wsReconnecting: reconnecting }, false, 'setWSReconnecting'),
      
      setWSLastMessage: (message) => 
        set({ wsLastMessage: message }, false, 'setWSLastMessage'),
      
      addNotification: (notification) => {
        const id = `${Date.now()}-${Math.random()}`;
        const newNotification = {
          ...notification,
          id,
          timestamp: new Date(),
          autoHide: notification.autoHide ?? true
        };
        
        set((state) => ({
          notifications: [...state.notifications, newNotification]
        }), false, 'addNotification');
        
        // Auto-remove after 5 seconds if autoHide is true
        if (newNotification.autoHide) {
          setTimeout(() => {
            set((state) => ({
              notifications: state.notifications.filter(n => n.id !== id)
            }), false, 'autoRemoveNotification');
          }, 5000);
        }
      },
      
      removeNotification: (id) => 
        set((state) => ({
          notifications: state.notifications.filter(n => n.id !== id)
        }), false, 'removeNotification'),
      
      clearNotifications: () => 
        set({ notifications: [] }, false, 'clearNotifications'),
      
      setIsRefreshing: (refreshing) => 
        set({ isRefreshing: refreshing }, false, 'setIsRefreshing')
    }),
    {
      name: 'phishnet-ui-store',
    }
  )
);
