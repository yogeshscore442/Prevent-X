import { Component, ErrorInfo, ReactNode } from 'react';
import { RefreshCw, Home, ShieldAlert } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  isRoot?: boolean;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('PREVENT-X UI ErrorBoundary caught an unhandled render error:', error, errorInfo);
    this.setState({ errorInfo });
  }

  public handleReload = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  public handleGoHome = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.href = '/';
  };

  public render() {
    if (this.state.hasError) {
      const isRoot = this.props.isRoot;

      return (
        <div
          className={`flex items-center justify-center p-6 ${
            isRoot ? 'min-h-screen bg-navy-950 text-slate-100' : 'min-h-[60vh] text-slate-100'
          }`}
        >
          <div className="max-w-xl w-full p-6 md:p-8 rounded-2xl bg-navy-900 border border-rose-800/60 shadow-2xl space-y-5 text-center">
            <div className="w-14 h-14 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center mx-auto text-rose-400 shadow-lg shadow-rose-950/50">
              <ShieldAlert className="w-8 h-8" />
            </div>

            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">
                {this.props.fallbackTitle || 'Component Rendering Recovered'}
              </h2>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                An unexpected exception was safely intercepted by the PREVENT-X Error Shield.
                The application session and security background services remain healthy.
              </p>
            </div>

            {this.state.error && (
              <div className="text-left bg-navy-950 border border-navy-800 rounded-xl p-3.5 space-y-1">
                <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                  Exception Telemetry
                </div>
                <div className="font-mono text-xs text-rose-300 break-words max-h-36 overflow-y-auto selection:bg-rose-900">
                  {this.state.error.message || String(this.state.error)}
                </div>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              <button
                type="button"
                onClick={this.handleReload}
                className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-600/20 transition-all cursor-pointer"
              >
                <RefreshCw className="w-4 h-4" />
                Reload Page
              </button>

              <button
                type="button"
                onClick={this.handleGoHome}
                className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-navy-800 hover:bg-navy-750 text-slate-300 text-xs font-medium border border-navy-700 transition-all cursor-pointer"
              >
                <Home className="w-4 h-4" />
                Return to Dashboard
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
