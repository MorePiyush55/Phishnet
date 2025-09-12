# PhishNet Frontend

A modern, responsive React-based SOC (Security Operations Center) dashboard for PhishNet email security analysis.

## Architecture

### Frontend State Strategy

- **React Query (@tanstack/react-query)**: Server state management for emails, details, audits
- **Zustand**: UI/local state management for filters, modals, WebSocket status
- **WebSocket**: Real-time updates that mutate/invalidate queries on relevant keys
- **Route Guards**: Check access token; silent refresh on 401 via refresh token

### Technology Stack

- **React 18** with TypeScript
- **Vite** for fast development and building
- **Tailwind CSS** for styling
- **React Query** for server state management
- **Zustand** for local state management
- **React Router** for routing
- **Lucide React** for icons
- **Axios** for API calls

## Features

### Authentication & Security
- JWT access/refresh token authentication
- Automatic token refresh on 401 errors
- Route guards with role-based access control
- Secure logout with token cleanup

### Real-time Updates
- WebSocket connection for live email updates
- Automatic query invalidation on relevant events
- Connection status monitoring with reconnection logic
- Real-time threat notifications

### Email Management
- Advanced filtering and search
- Bulk actions (quarantine, delete, mark safe)
- Risk score visualization
- Status management
- Detailed email analysis

### SOC Dashboard
- Real-time system statistics
- Threat level indicators
- Live alerts feed
- Email analysis panel
- Link and attachment analysis

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Python backend server running on port 8000

### Installation

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

### Environment Configuration

Create a `.env` file in the frontend directory:

```env
REACT_APP_API_URL=http://localhost:8000
```

## Project Structure

```
frontend/
├── src/
│   ├── components/         # React components
│   │   ├── SOCDashboard.tsx
│   │   └── LoginPage.tsx
│   ├── hooks/             # Custom React hooks
│   │   ├── useAuth.ts
│   │   ├── useApiQueries.ts
│   │   └── useWebSocket.ts
│   ├── services/          # API and WebSocket services
│   │   ├── apiService.ts
│   │   └── webSocketService.ts
│   ├── stores/            # Zustand stores
│   │   └── uiStore.ts
│   ├── App.tsx            # Main app component
│   ├── index.tsx          # Entry point
│   └── index.css          # Global styles
├── public/                # Static assets
├── package.json           # Dependencies and scripts
├── tsconfig.json          # TypeScript configuration
├── vite.config.ts         # Vite configuration
├── tailwind.config.js     # Tailwind CSS configuration
└── README.md              # This file
```

## API Integration

### Authentication Flow
1. User logs in with username/password
2. Backend returns access_token and refresh_token
3. Access token used for API requests
4. On 401 error, automatic silent refresh using refresh_token
5. On refresh failure, redirect to login

### WebSocket Integration
- Connects automatically after authentication
- Handles real-time events: email_processed, email_updated, threat_detected, system_alert
- Automatically updates React Query cache based on events
- Shows notifications for important events
- Handles reconnection with exponential backoff

### Query Management
- Emails are cached and paginated
- Individual email details cached separately
- Automatic invalidation on WebSocket events
- Background refetching for fresh data
- Optimistic updates for user actions

## State Management

### Zustand Store (UI State)
- Search filters and form state
- Modal and panel visibility
- WebSocket connection status
- Notifications queue
- Loading states

### React Query (Server State)
- Email lists with pagination
- Individual email details
- Link analysis data
- Audit logs
- System statistics

## Authentication & Authorization

### User Roles
- **admin**: Full access to all features
- **analyst**: Email management and analysis
- **viewer**: Read-only access

### Route Protection
- All routes except `/login` require authentication
- Role-based access control for sensitive operations
- Automatic redirect to login on authentication failure

## Real-time Features

### WebSocket Events
- `email_processed`: New email analysis completed
- `email_updated`: Email status changed by another user
- `threat_detected`: High-priority threat identified
- `system_alert`: System status or error notifications
- `user_action`: Actions performed by other users

### Notifications
- Auto-hide for informational messages
- Persistent for critical alerts
- Real-time updates for threat detection
- User action notifications

## Development

### Available Scripts

- `npm run dev`: Start development server
- `npm run build`: Build for production
- `npm run preview`: Preview production build
- `npm run type-check`: Run TypeScript type checking

### Code Organization

- **Components**: Presentational and container components
- **Hooks**: Custom hooks for business logic
- **Services**: API and external service integrations
- **Stores**: State management
- **Types**: TypeScript type definitions

### Development Guidelines

1. Use TypeScript for all new code
2. Follow React hooks patterns
3. Keep components focused and single-purpose
4. Use React Query for all server state
5. Use Zustand only for UI/local state
6. Write meaningful commit messages

## Deployment

### Production Build

```bash
npm run build
```

### Environment Variables

Set the following environment variables for production:

- `REACT_APP_API_URL`: Backend API URL

### Hosting

The built application in the `dist/` directory can be served by any static file server.

## Troubleshooting

### Common Issues

1. **WebSocket connection fails**
   - Check backend server is running
   - Verify WebSocket endpoint configuration
   - Check authentication token validity

2. **API requests fail**
   - Verify backend server is accessible
   - Check CORS configuration
   - Verify authentication tokens

3. **Build fails**
   - Clear node_modules and reinstall
   - Check TypeScript errors
   - Verify all dependencies are installed

### Debug Mode

Enable React Query DevTools in development to inspect cache state and query behavior.

## Security Considerations

- All API requests include authentication headers
- Tokens stored in localStorage (consider httpOnly cookies for production)
- WebSocket connections authenticate on connect
- Input validation and sanitization
- HTTPS recommended for production

## Performance

- Code splitting with dynamic imports
- Query caching with appropriate stale times
- Optimistic updates for better UX
- Image optimization and lazy loading
- Bundle size optimization with tree shaking

## Contributing

1. Create feature branch from main
2. Follow existing code patterns
3. Add TypeScript types for new features
4. Test with both mock and real data
5. Update documentation as needed

## License

This project is part of the PhishNet security platform.
