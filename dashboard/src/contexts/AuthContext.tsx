import { createContext, useContext, useState, useCallback, ReactNode } from 'react';
import { MockUser } from '../types/mockUsers';
import { generateMockToken } from '../api/queryvault';

interface AuthState {
  user: MockUser;
  jwt: string;
}

interface AuthContextValue {
  auth: AuthState | null;
  login: (user: MockUser) => Promise<void>;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [loading, setLoading] = useState(false);

  const login = useCallback(async (user: MockUser) => {
    setLoading(true);
    try {
      const result = await generateMockToken(user.oid);
      if (result.data) {
        setAuth({ user, jwt: result.data.jwt_token });
      } else {
        throw new Error(result.error ?? 'Failed to generate token');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => setAuth(null), []);

  return (
    <AuthContext.Provider value={{ auth, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
