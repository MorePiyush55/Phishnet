"""
TypeScript API Client Generator - Generate TypeScript client from FastAPI OpenAPI spec
Eliminates contract drift between frontend and backend
"""

import json
import logging
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from datetime import datetime
import httpx
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class TypeScriptConfig:
    """TypeScript client generation configuration"""
    api_base_url: str = "http://localhost:8080"
    output_dir: str = "frontend/src/api"
    client_name: str = "PhishNetApiClient"
    include_auth: bool = True
    generate_types: bool = True
    generate_hooks: bool = True  # React Query hooks
    generate_stores: bool = True  # Zustand stores
    axios_client: bool = True
    fetch_client: bool = False

class TypeScriptGenerator:
    """
    Generate TypeScript API client from FastAPI OpenAPI specification
    
    Features:
    - Type-safe API client generation
    - React Query hooks generation
    - Zustand store generation
    - Authentication handling
    - Error handling
    - Request/response validation
    """
    
    def __init__(self, config: TypeScriptConfig):
        self.config = config
        self.spec: Optional[Dict[str, Any]] = None
        self.types: Set[str] = set()
        self.endpoints: List[Dict[str, Any]] = []
    
    async def fetch_openapi_spec(self) -> bool:
        """Fetch OpenAPI specification from FastAPI"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.config.api_base_url}/openapi.json")
                response.raise_for_status()
                self.spec = response.json()
                
                logger.info(f"Fetched OpenAPI spec from {self.config.api_base_url}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to fetch OpenAPI spec: {e}")
            return False
    
    def load_openapi_spec(self, spec_path: str) -> bool:
        """Load OpenAPI specification from file"""
        try:
            with open(spec_path, 'r') as f:
                self.spec = json.load(f)
                
            logger.info(f"Loaded OpenAPI spec from {spec_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load OpenAPI spec: {e}")
            return False
    
    def _parse_schema_type(self, schema: Dict[str, Any], name: str = "") -> str:
        """Parse OpenAPI schema to TypeScript type"""
        if not schema:
            return "any"
        
        schema_type = schema.get("type", "")
        
        if schema_type == "string":
            enum_values = schema.get("enum")
            if enum_values:
                return " | ".join(f'"{value}"' for value in enum_values)
            return "string"
        elif schema_type == "integer":
            return "number"
        elif schema_type == "number":
            return "number"
        elif schema_type == "boolean":
            return "boolean"
        elif schema_type == "array":
            items = schema.get("items", {})
            item_type = self._parse_schema_type(items)
            return f"Array<{item_type}>"
        elif schema_type == "object":
            properties = schema.get("properties", {})
            required = schema.get("required", [])
            
            if not properties:
                return "Record<string, any>"
            
            type_def = "{\n"
            for prop_name, prop_schema in properties.items():
                optional = "" if prop_name in required else "?"
                prop_type = self._parse_schema_type(prop_schema, prop_name)
                type_def += f"  {prop_name}{optional}: {prop_type};\n"
            type_def += "}"
            
            return type_def
        elif "$ref" in schema:
            ref_path = schema["$ref"]
            type_name = ref_path.split("/")[-1]
            self.types.add(type_name)
            return type_name
        else:
            return "any"
    
    def _generate_types(self) -> str:
        """Generate TypeScript type definitions"""
        if not self.spec:
            return ""
        
        types_code = '''// Generated TypeScript types for PhishNet API
// Do not edit manually - regenerate using the TypeScript generator

'''
        
        # Generate types from components/schemas
        components = self.spec.get("components", {})
        schemas = components.get("schemas", {})
        
        for schema_name, schema_def in schemas.items():
            type_def = self._parse_schema_type(schema_def, schema_name)
            
            # Add description if available
            description = schema_def.get("description", "")
            if description:
                types_code += f"/**\n * {description}\n */\n"
            
            types_code += f"export interface {schema_name} {type_def}\n\n"
        
        # Generate common types
        types_code += '''// Common API types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface AuthToken {
  access_token: string;
  token_type: string;
}

export interface ApiError {
  detail: string;
  error_code?: string;
}

'''
        
        return types_code
    
    def _generate_api_client(self) -> str:
        """Generate main API client class"""
        if not self.spec:
            return ""
        
        client_code = f'''// Generated API client for PhishNet
// Do not edit manually - regenerate using the TypeScript generator

import axios, {{ AxiosInstance, AxiosResponse, AxiosError }} from 'axios';
import {{ ApiResponse, PaginatedResponse, AuthToken, ApiError }} from './types';

export class {self.config.client_name} {{
  private client: AxiosInstance;
  private authToken: string | null = null;
  
  constructor(baseURL: string = '{self.config.api_base_url}') {{
    this.client = axios.create({{
      baseURL,
      timeout: 30000,
      headers: {{
        'Content-Type': 'application/json',
      }},
    }});
    
    // Request interceptor for auth
    this.client.interceptors.request.use((config) => {{
      if (this.authToken) {{
        config.headers.Authorization = `Bearer ${{this.authToken}}`;
      }}
      return config;
    }});
    
    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {{
        if (error.response?.status === 401) {{
          this.authToken = null;
          // Trigger logout or redirect to login
          window.dispatchEvent(new CustomEvent('phishnet:unauthorized'));
        }}
        return Promise.reject(error);
      }}
    );
  }}
  
  /**
   * Set authentication token
   */
  setAuthToken(token: string): void {{
    this.authToken = token;
  }}
  
  /**
   * Clear authentication token
   */
  clearAuthToken(): void {{
    this.authToken = null;
  }}
  
  /**
   * Get current auth token
   */
  getAuthToken(): string | null {{
    return this.authToken;
  }}
  
  /**
   * Handle API response
   */
  private handleResponse<T>(response: AxiosResponse): ApiResponse<T> {{
    return {{
      success: true,
      data: response.data,
    }};
  }}
  
  /**
   * Handle API error
   */
  private handleError(error: AxiosError): ApiResponse<never> {{
    const errorData = error.response?.data as ApiError;
    return {{
      success: false,
      error: errorData?.detail || error.message,
    }};
  }}

'''
        
        # Generate endpoint methods
        paths = self.spec.get("paths", {})
        
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method not in ["get", "post", "put", "delete", "patch"]:
                    continue
                
                operation_id = operation.get("operationId", "")
                summary = operation.get("summary", "")
                parameters = operation.get("parameters", [])
                request_body = operation.get("requestBody", {})
                responses = operation.get("responses", {})
                
                # Generate method name
                method_name = operation_id or f"{method}_{path.replace('/', '_').replace('{', '').replace('}', '')}"
                method_name = method_name.replace('-', '_')
                
                # Generate parameters
                path_params = [p for p in parameters if p.get("in") == "path"]
                query_params = [p for p in parameters if p.get("in") == "query"]
                
                # Build method signature
                params = []
                for param in path_params:
                    param_name = param["name"]
                    param_type = self._parse_schema_type(param.get("schema", {}))
                    params.append(f"{param_name}: {param_type}")
                
                if request_body:
                    content = request_body.get("content", {})
                    json_content = content.get("application/json", {})
                    if json_content:
                        schema = json_content.get("schema", {})
                        body_type = self._parse_schema_type(schema)
                        params.append(f"data: {body_type}")
                
                if query_params:
                    query_type = "{\n"
                    for param in query_params:
                        param_name = param["name"]
                        param_type = self._parse_schema_type(param.get("schema", {}))
                        optional = "?" if not param.get("required", False) else ""
                        query_type += f"    {param_name}{optional}: {param_type};\n"
                    query_type += "  }"
                    params.append(f"params?: {query_type}")
                
                # Determine return type
                success_response = responses.get("200", responses.get("201", {}))
                content = success_response.get("content", {})
                json_content = content.get("application/json", {})
                if json_content:
                    schema = json_content.get("schema", {})
                    return_type = self._parse_schema_type(schema)
                else:
                    return_type = "any"
                
                # Generate method
                params_str = ", ".join(params)
                
                client_code += f'''  /**
   * {summary}
   */
  async {method_name}({params_str}): Promise<ApiResponse<{return_type}>> {{
    try {{
      const response = await this.client.{method}(
        `{path}`{', data' if request_body else ''}{', { params }' if query_params else ''}
      );
      return this.handleResponse<{return_type}>(response);
    }} catch (error) {{
      return this.handleError(error as AxiosError);
    }}
  }}

'''
        
        client_code += "}\n"
        return client_code
    
    def _generate_react_query_hooks(self) -> str:
        """Generate React Query hooks"""
        if not self.config.generate_hooks:
            return ""
        
        hooks_code = '''// Generated React Query hooks for PhishNet API
// Do not edit manually - regenerate using the TypeScript generator

import { useQuery, useMutation, useQueryClient, UseQueryOptions, UseMutationOptions } from '@tanstack/react-query';
import { PhishNetApiClient } from './client';
import * as Types from './types';

// Create API client instance
const apiClient = new PhishNetApiClient();

// Auth token management
export const setApiToken = (token: string) => {
  apiClient.setAuthToken(token);
};

export const clearApiToken = () => {
  apiClient.clearAuthToken();
};

// Query keys
export const queryKeys = {
  emails: ['emails'] as const,
  email: (id: number) => ['emails', id] as const,
  emailStats: ['emails', 'stats'] as const,
  health: ['health'] as const,
  links: ['links'] as const,
  link: (id: number) => ['links', id] as const,
} as const;

// Email hooks
export const useEmails = (
  params?: { page?: number; limit?: number; status?: string },
  options?: UseQueryOptions<Types.PaginatedResponse<Types.Email>>
) => {
  return useQuery({
    queryKey: [...queryKeys.emails, params],
    queryFn: async () => {
      const response = await apiClient.getEmails(params);
      if (!response.success) throw new Error(response.error);
      return response.data!;
    },
    ...options,
  });
};

export const useEmail = (
  id: number,
  options?: UseQueryOptions<Types.Email>
) => {
  return useQuery({
    queryKey: queryKeys.email(id),
    queryFn: async () => {
      const response = await apiClient.getEmail(id);
      if (!response.success) throw new Error(response.error);
      return response.data!;
    },
    enabled: !!id,
    ...options,
  });
};

export const useEmailStats = (
  options?: UseQueryOptions<Types.EmailStats>
) => {
  return useQuery({
    queryKey: queryKeys.emailStats,
    queryFn: async () => {
      const response = await apiClient.getEmailStats();
      if (!response.success) throw new Error(response.error);
      return response.data!;
    },
    ...options,
  });
};

// Email mutations
export const useCreateEmail = (
  options?: UseMutationOptions<Types.Email, Error, Types.EmailCreate>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async (data: Types.EmailCreate) => {
      const response = await apiClient.createEmail(data);
      if (!response.success) throw new Error(response.error);
      return response.data!;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.emails });
      queryClient.invalidateQueries({ queryKey: queryKeys.emailStats });
    },
    ...options,
  });
};

export const useUpdateEmail = (
  options?: UseMutationOptions<Types.Email, Error, { id: number; data: Types.EmailUpdate }>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async ({ id, data }) => {
      const response = await apiClient.updateEmail(id, data);
      if (!response.success) throw new Error(response.error);
      return response.data!;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.emails });
      queryClient.invalidateQueries({ queryKey: queryKeys.email(data.id) });
      queryClient.invalidateQueries({ queryKey: queryKeys.emailStats });
    },
    ...options,
  });
};

export const useDeleteEmail = (
  options?: UseMutationOptions<void, Error, number>
) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await apiClient.deleteEmail(id);
      if (!response.success) throw new Error(response.error);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.emails });
      queryClient.invalidateQueries({ queryKey: queryKeys.emailStats });
    },
    ...options,
  });
};

// Authentication hooks
export const useLogin = (
  options?: UseMutationOptions<Types.AuthToken, Error, { email: string; password: string }>
) => {
  return useMutation({
    mutationFn: async ({ email, password }) => {
      const response = await apiClient.login({ username: email, password });
      if (!response.success) throw new Error(response.error);
      
      // Set token for future requests
      setApiToken(response.data!.access_token);
      
      return response.data!;
    },
    ...options,
  });
};

// Health check hook
export const useHealth = (
  options?: UseQueryOptions<Types.HealthResponse>
) => {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: async () => {
      const response = await apiClient.getHealth();
      if (!response.success) throw new Error(response.error);
      return response.data!;
    },
    refetchInterval: 30000, // Check every 30 seconds
    ...options,
  });
};

// WebSocket hook for real-time updates
export const useWebSocketUpdates = () => {
  const queryClient = useQueryClient();
  
  React.useEffect(() => {
    const ws = new WebSocket('ws://localhost:8080/ws');
    
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      
      switch (message.type) {
        case 'email_created':
        case 'email_updated':
        case 'email_analyzed':
          queryClient.invalidateQueries({ queryKey: queryKeys.emails });
          queryClient.invalidateQueries({ queryKey: queryKeys.emailStats });
          break;
        case 'link_analyzed':
          queryClient.invalidateQueries({ queryKey: queryKeys.links });
          break;
      }
    };
    
    return () => ws.close();
  }, [queryClient]);
};

'''
        
        return hooks_code
    
    def _generate_zustand_stores(self) -> str:
        """Generate Zustand stores"""
        if not self.config.generate_stores:
            return ""
        
        stores_code = '''// Generated Zustand stores for PhishNet
// Do not edit manually - regenerate using the TypeScript generator

import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import * as Types from './types';

// Auth store
interface AuthState {
  user: Types.User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (token: string, user: Types.User) => void;
  logout: () => void;
  updateUser: (user: Partial<Types.User>) => void;
}

export const useAuthStore = create<AuthState>()(
  devtools(
    persist(
      (set, get) => ({
        user: null,
        token: null,
        isAuthenticated: false,
        
        login: (token: string, user: Types.User) => {
          set({ token, user, isAuthenticated: true });
          // Set token in API client
          import('./hooks').then(({ setApiToken }) => {
            setApiToken(token);
          });
        },
        
        logout: () => {
          set({ token: null, user: null, isAuthenticated: false });
          // Clear token from API client
          import('./hooks').then(({ clearApiToken }) => {
            clearApiToken();
          });
        },
        
        updateUser: (userData: Partial<Types.User>) => {
          const { user } = get();
          if (user) {
            set({ user: { ...user, ...userData } });
          }
        },
      }),
      {
        name: 'phishnet-auth',
        partialize: (state) => ({
          token: state.token,
          user: state.user,
          isAuthenticated: state.isAuthenticated,
        }),
      }
    ),
    { name: 'auth-store' }
  )
);

// Dashboard store
interface DashboardState {
  emailFilters: {
    status?: string;
    search?: string;
    dateRange?: [string, string];
  };
  selectedEmails: number[];
  viewMode: 'list' | 'grid' | 'table';
  setEmailFilters: (filters: Partial<DashboardState['emailFilters']>) => void;
  setSelectedEmails: (ids: number[]) => void;
  toggleEmailSelection: (id: number) => void;
  setViewMode: (mode: DashboardState['viewMode']) => void;
  clearSelections: () => void;
}

export const useDashboardStore = create<DashboardState>()(
  devtools(
    (set, get) => ({
      emailFilters: {},
      selectedEmails: [],
      viewMode: 'table',
      
      setEmailFilters: (filters) => {
        set((state) => ({
          emailFilters: { ...state.emailFilters, ...filters },
        }));
      },
      
      setSelectedEmails: (ids) => {
        set({ selectedEmails: ids });
      },
      
      toggleEmailSelection: (id) => {
        const { selectedEmails } = get();
        const newSelection = selectedEmails.includes(id)
          ? selectedEmails.filter((emailId) => emailId !== id)
          : [...selectedEmails, id];
        set({ selectedEmails: newSelection });
      },
      
      setViewMode: (mode) => {
        set({ viewMode: mode });
      },
      
      clearSelections: () => {
        set({ selectedEmails: [] });
      },
    }),
    { name: 'dashboard-store' }
  )
);

// Notifications store
interface NotificationState {
  notifications: Array<{
    id: string;
    type: 'success' | 'error' | 'warning' | 'info';
    title: string;
    message: string;
    timestamp: Date;
  }>;
  addNotification: (notification: Omit<NotificationState['notifications'][0], 'id' | 'timestamp'>) => void;
  removeNotification: (id: string) => void;
  clearNotifications: () => void;
}

export const useNotificationStore = create<NotificationState>()(
  devtools(
    (set) => ({
      notifications: [],
      
      addNotification: (notification) => {
        const id = Math.random().toString(36).substr(2, 9);
        const newNotification = {
          ...notification,
          id,
          timestamp: new Date(),
        };
        
        set((state) => ({
          notifications: [newNotification, ...state.notifications].slice(0, 10), // Keep last 10
        }));
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
          set((state) => ({
            notifications: state.notifications.filter((n) => n.id !== id),
          }));
        }, 5000);
      },
      
      removeNotification: (id) => {
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        }));
      },
      
      clearNotifications: () => {
        set({ notifications: [] });
      },
    }),
    { name: 'notification-store' }
  )
);

// Settings store
interface SettingsState {
  theme: 'light' | 'dark';
  autoRefresh: boolean;
  refreshInterval: number; // seconds
  enableNotifications: boolean;
  compactMode: boolean;
  setTheme: (theme: SettingsState['theme']) => void;
  setAutoRefresh: (enabled: boolean) => void;
  setRefreshInterval: (interval: number) => void;
  setEnableNotifications: (enabled: boolean) => void;
  setCompactMode: (enabled: boolean) => void;
}

export const useSettingsStore = create<SettingsState>()(
  devtools(
    persist(
      (set) => ({
        theme: 'light',
        autoRefresh: true,
        refreshInterval: 30,
        enableNotifications: true,
        compactMode: false,
        
        setTheme: (theme) => set({ theme }),
        setAutoRefresh: (autoRefresh) => set({ autoRefresh }),
        setRefreshInterval: (refreshInterval) => set({ refreshInterval }),
        setEnableNotifications: (enableNotifications) => set({ enableNotifications }),
        setCompactMode: (compactMode) => set({ compactMode }),
      }),
      {
        name: 'phishnet-settings',
      }
    ),
    { name: 'settings-store' }
  )
);

'''
        
        return stores_code
    
    def _generate_index_file(self) -> str:
        """Generate index file that exports everything"""
        index_code = '''// Generated PhishNet API client exports
// Do not edit manually - regenerate using the TypeScript generator

// Types
export * from './types';

// API Client
export { PhishNetApiClient } from './client';

// React Query Hooks
export * from './hooks';

// Zustand Stores
export * from './stores';

// Default client instance
import { PhishNetApiClient } from './client';
export const apiClient = new PhishNetApiClient();

'''
        
        return index_code
    
    async def generate_client(self) -> bool:
        """Generate complete TypeScript client"""
        try:
            # Fetch OpenAPI spec
            if not await self.fetch_openapi_spec():
                return False
            
            # Create output directory
            output_dir = Path(self.config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate types
            types_code = self._generate_types()
            types_file = output_dir / "types.ts"
            with open(types_file, 'w') as f:
                f.write(types_code)
            
            # Generate API client
            client_code = self._generate_api_client()
            client_file = output_dir / "client.ts"
            with open(client_file, 'w') as f:
                f.write(client_code)
            
            # Generate React Query hooks
            if self.config.generate_hooks:
                hooks_code = self._generate_react_query_hooks()
                hooks_file = output_dir / "hooks.ts"
                with open(hooks_file, 'w') as f:
                    f.write(hooks_code)
            
            # Generate Zustand stores
            if self.config.generate_stores:
                stores_code = self._generate_zustand_stores()
                stores_file = output_dir / "stores.ts"
                with open(stores_file, 'w') as f:
                    f.write(stores_code)
            
            # Generate index file
            index_code = self._generate_index_file()
            index_file = output_dir / "index.ts"
            with open(index_file, 'w') as f:
                f.write(index_code)
            
            # Generate package.json for dependencies
            package_json = {
                "name": "@phishnet/api-client",
                "version": "1.0.0",
                "description": "TypeScript API client for PhishNet",
                "main": "index.ts",
                "dependencies": {
                    "axios": "^1.6.0",
                    "@tanstack/react-query": "^5.0.0",
                    "zustand": "^4.4.0"
                },
                "devDependencies": {
                    "typescript": "^5.0.0",
                    "@types/react": "^18.0.0"
                }
            }
            
            package_file = output_dir / "package.json"
            with open(package_file, 'w') as f:
                json.dump(package_json, f, indent=2)
            
            # Generate README
            readme_content = f'''# PhishNet TypeScript API Client

Generated TypeScript client for the PhishNet API.

## Installation

```bash
npm install axios @tanstack/react-query zustand
```

## Usage

### Basic API Client

```typescript
import {{ PhishNetApiClient }} from './client';

const client = new PhishNetApiClient('http://localhost:8080');

// Login
const response = await client.login({{ username: 'admin@phishnet.local', password: 'admin' }});
if (response.success) {{
  client.setAuthToken(response.data.access_token);
}}

// Get emails
const emails = await client.getEmails({{ page: 1, limit: 10 }});
```

### React Query Hooks

```typescript
import {{ useEmails, useLogin }} from './hooks';

function EmailList() {{
  const {{ data: emails, isLoading }} = useEmails({{ page: 1, limit: 10 }});
  const loginMutation = useLogin();
  
  // Use the data...
}}
```

### Zustand Stores

```typescript
import {{ useAuthStore, useDashboardStore }} from './stores';

function Dashboard() {{
  const {{ user, isAuthenticated }} = useAuthStore();
  const {{ emailFilters, setEmailFilters }} = useDashboardStore();
  
  // Use the state...
}}
```

## Generated Files

- `types.ts` - TypeScript type definitions
- `client.ts` - Main API client class
- `hooks.ts` - React Query hooks
- `stores.ts` - Zustand stores
- `index.ts` - Main exports

## Regeneration

To regenerate the client after API changes:

```python
from app.core.typescript_generator import TypeScriptGenerator, TypeScriptConfig

config = TypeScriptConfig(
    api_base_url="http://localhost:8080",
    output_dir="frontend/src/api"
)

generator = TypeScriptGenerator(config)
await generator.generate_client()
```

Generated on: {datetime.now().isoformat()}
'''
            
            readme_file = output_dir / "README.md"
            with open(readme_file, 'w') as f:
                f.write(readme_content)
            
            logger.info(f"TypeScript client generated successfully in {output_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate TypeScript client: {e}")
            return False

# CLI function for generating client
async def generate_typescript_client(
    api_url: str = "http://localhost:8080",
    output_dir: str = "frontend/src/api"
):
    """Generate TypeScript client from running FastAPI server"""
    
    config = TypeScriptConfig(
        api_base_url=api_url,
        output_dir=output_dir,
        generate_hooks=True,
        generate_stores=True
    )
    
    generator = TypeScriptGenerator(config)
    success = await generator.generate_client()
    
    if success:
        print(f"✅ TypeScript client generated successfully in {output_dir}")
        print("\nNext steps:")
        print(f"1. cd {output_dir}")
        print("2. npm install axios @tanstack/react-query zustand")
        print("3. Import and use the generated client in your React app")
    else:
        print("❌ Failed to generate TypeScript client")

# Example usage
async def example_typescript_generation():
    """Example of generating TypeScript client"""
    
    config = TypeScriptConfig(
        api_base_url="http://localhost:8080",
        output_dir="generated/typescript",
        client_name="PhishNetApiClient",
        generate_hooks=True,
        generate_stores=True
    )
    
    generator = TypeScriptGenerator(config)
    
    # Generate from running API
    success = await generator.generate_client()
    
    if success:
        print("TypeScript client generated successfully!")
        print("Files created:")
        print("- types.ts (Type definitions)")
        print("- client.ts (API client)")
        print("- hooks.ts (React Query hooks)")
        print("- stores.ts (Zustand stores)")
        print("- index.ts (Main exports)")
        print("- README.md (Documentation)")
    else:
        print("Failed to generate TypeScript client")

if __name__ == "__main__":
    import asyncio
    asyncio.run(example_typescript_generation())
