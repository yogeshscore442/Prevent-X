import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ShieldAlert, Lock, Mail, AlertCircle, ArrowRight, Loader2, Sparkles, Eye, EyeOff, KeyRound } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [orgSlug, setOrgSlug] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const setCredentials = (userEmail: string, userPass: string, slug?: string) => {
    setEmail(userEmail);
    setPassword(userPass);
    if (slug) setOrgSlug(slug);
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login(email, password, orgSlug || undefined);
      navigate('/');
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      const msg =
        (typeof detail === 'string'
          ? detail
          : detail?.message || (Array.isArray(detail) ? detail[0]?.msg : null)) ||
        'Authentication failed. Please verify your credentials.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-navy-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans">
      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
        <div className="inline-flex w-14 h-14 rounded-2xl bg-gradient-to-tr from-cyan-600 to-blue-500 items-center justify-center shadow-xl shadow-cyan-500/20 mb-4 border border-cyan-400/30">
          <ShieldAlert className="w-8 h-8 text-white" />
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-white">PREVENT-X</h2>
        <p className="mt-1 text-sm text-cyan-400 font-mono">
          AI-Era Virtual Patching Platform for Indian SMBs
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md px-4 sm:px-0">
        <div className="bg-navy-900 py-8 px-6 shadow-2xl rounded-2xl border border-navy-800 sm:px-10">
          {/* Demo Accounts Quick-Select */}
          <div className="mb-6 p-3 bg-navy-850/90 rounded-xl border border-navy-700/80 text-xs">
            <div className="flex items-center gap-1.5 text-cyan-400 font-semibold mb-2">
              <KeyRound className="w-3.5 h-3.5" />
              <span>Quick Login Accounts (One-Click)</span>
            </div>
            <div className="space-y-1.5">
              <button
                type="button"
                onClick={() => setCredentials('admin@preventx.internal', 'Admin@12345', 'smb-default')}
                className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-navy-900 hover:bg-cyan-950/60 border border-navy-700 hover:border-cyan-700/60 text-left transition-colors group cursor-pointer"
              >
                <div>
                  <div className="text-[11px] font-medium text-slate-200 group-hover:text-cyan-300">
                    Lead Administrator (Super Admin)
                  </div>
                  <div className="text-[10px] text-slate-400 font-mono">
                    admin@preventx.internal • Admin@12345
                  </div>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-900/60 text-cyan-300 font-mono">
                  Fill
                </span>
              </button>

              <button
                type="button"
                onClick={() => setCredentials('yogesh@smbclinet.in', 'Admin@12345', 'smb-default')}
                className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-navy-900 hover:bg-cyan-950/60 border border-navy-700 hover:border-cyan-700/60 text-left transition-colors group cursor-pointer"
              >
                <div>
                  <div className="text-[11px] font-medium text-slate-200 group-hover:text-cyan-300">
                    Yogesh (Security Analyst)
                  </div>
                  <div className="text-[10px] text-slate-400 font-mono">
                    yogesh@smbclinet.in • Admin@12345
                  </div>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-900/60 text-cyan-300 font-mono">
                  Fill
                </span>
              </button>

              <button
                type="button"
                onClick={() => setCredentials('admin@bharatkart.in', 'Admin@12345', 'bharatkart')}
                className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-navy-900 hover:bg-cyan-950/60 border border-navy-700 hover:border-cyan-700/60 text-left transition-colors group cursor-pointer"
              >
                <div>
                  <div className="text-[11px] font-medium text-slate-200 group-hover:text-cyan-300">
                    BharatKart Enterprise (E-Commerce)
                  </div>
                  <div className="text-[10px] text-slate-400 font-mono">
                    admin@bharatkart.in • Admin@12345
                  </div>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-900/60 text-cyan-300 font-mono">
                  Fill
                </span>
              </button>
            </div>
          </div>

          <form className="space-y-5" onSubmit={handleSubmit}>
            {error && (
              <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1.5">
                Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@preventx.internal"
                  className="w-full pl-9 pr-3 py-2.5 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition-all"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1.5">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-10 py-2.5 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200 transition-colors"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-1.5">
                Organization Slug <span className="text-slate-600 font-normal lowercase">(optional)</span>
              </label>
              <input
                type="text"
                value={orgSlug}
                onChange={(e) => setOrgSlug(e.target.value)}
                placeholder="smb-default"
                className="w-full px-3 py-2 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm shadow-lg shadow-cyan-600/20 disabled:opacity-50 transition-all cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Verifying Credentials...</span>
                </>
              ) : (
                <>
                  <span>Sign In</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          <div className="mt-6 pt-6 border-t border-navy-800 text-center">
            <Link
              to="/bootstrap"
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1.5 transition-colors"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Initial Platform Setup? Bootstrap Admin</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

