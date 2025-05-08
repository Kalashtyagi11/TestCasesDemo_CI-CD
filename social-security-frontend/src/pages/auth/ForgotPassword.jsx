import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import authService from '../../services/authService';
import '../../assets/css/Auth.css';

const ForgotPassword = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await authService.forgotPassword(email);
      setMessage('Password reset instructions have been sent to your email.');
      setError('');
    } catch (err) {
      setError(err.message || 'Failed to process password reset request. Please try again.');
      setMessage('');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h2>Forgot Password</h2>
        {message && <div className="success-message">{message}</div>}
        {error && <div className="error-message">{error}</div>}
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email">Email Address</label>
            <input
              type="email"
              id="email"
              name="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={loading}
            />
          </div>
          <button className="auth-button" type="submit" disabled={loading}>
            {loading ? 'Sending...' : 'Reset Password'}
          </button>
          <div className="auth-link">
            <a href="/auth/login">Back to Login</a>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ForgotPassword; 