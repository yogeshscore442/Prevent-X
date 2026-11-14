import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { LoginPage } from '@/pages/LoginPage';
import { AuthProvider } from '@/contexts/AuthContext';

describe('LoginPage Component', () => {
  it('renders login form with email, password, and submit button', () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </BrowserRouter>
    );

    expect(screen.getByText('PREVENT-X')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('admin@preventx.internal')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('••••••••••••')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('allows user input in email and password fields', () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </BrowserRouter>
    );

    const emailInput = screen.getByPlaceholderText('admin@preventx.internal') as HTMLInputElement;
    const passwordInput = screen.getByPlaceholderText('••••••••••••') as HTMLInputElement;

    fireEvent.change(emailInput, { target: { value: 'admin@alphacorp.in' } });
    fireEvent.change(passwordInput, { target: { value: 'AlphaAdminPass123!' } });

    expect(emailInput.value).toBe('admin@alphacorp.in');
    expect(passwordInput.value).toBe('AlphaAdminPass123!');
  });
});

