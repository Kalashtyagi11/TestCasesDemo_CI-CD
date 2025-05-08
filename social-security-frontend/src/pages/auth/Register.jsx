import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import authService from '../../services/authService';
import '../../assets/css/Auth.css';

const Register = () => {
    const navigate = useNavigate();
    const [step, setStep] = useState(1);
    const [formData, setFormData] = useState({
        email: '',
        verificationCode: '',
        password: '',
        confirmPassword: '',
        firstName: '',
        lastName: '',
        mobileNumber: ''
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState('');

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
        setError('');
    };

    const handleInitiateRegistration = async (e) => {
        debugger
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
            await authService.initiateRegistration(formData.email);
            setStep(2);
            setSuccess('Verification code sent to your email');
        } catch (err) {
            setError(err.message || 'Failed to initiate registration');
        } finally {
            setLoading(false);
        }
    };

    const handleCompleteRegistration = async (e) => {
        e.preventDefault();
        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        setLoading(true);
        setError('');
        try {
            const response = await authService.verifyAndCompleteRegistration({
                email: formData.email,
                code: formData.verificationCode,
                password: formData.password,
                firstName: formData.firstName,
                lastName: formData.lastName,
                mobileNumber: formData.mobileNumber
            });

            // Store token and user data
            localStorage.setItem('token', response.Data.Token);
            localStorage.setItem('user', JSON.stringify(response.Data.User));

            setSuccess('Registration completed successfully! Redirecting to dashboard...');
            setTimeout(() => navigate('/dashboard'), 2000);
        } catch (err) {
            setError(err.message || 'Registration failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="auth-container">
            <div className="auth-card">
                <h2>Create Account</h2>
                {error && <div className="error-message">{error}</div>}
                {success && <div className="success-message">{success}</div>}

                {step === 1 && (
                    <form onSubmit={handleInitiateRegistration}>
                        <div className="form-group">
                            <label htmlFor="email">Email</label>
                            <input
                                type="email"
                                id="email"
                                name="email"
                                value={formData.email}
                                onChange={handleChange}
                                required
                                placeholder="Enter your email"
                                disabled={loading}
                            />
                        </div>
                        <button className="auth-button" type="submit" disabled={loading}>
                            {loading ? 'Sending...' : 'Send Verification Code'}
                        </button>
                    </form>
                )}

                {step === 2 && (
                    <form onSubmit={handleCompleteRegistration}>
                        <div className="form-group">
                            <label htmlFor="verificationCode">Verification Code</label>
                            <input
                                type="text"
                                id="verificationCode"
                                name="verificationCode"
                                value={formData.verificationCode}
                                onChange={handleChange}
                                required
                                placeholder="Enter verification code"
                                disabled={loading}
                            />
                        </div>
                        <div className="form-group">
                            <label htmlFor="firstName">First Name</label>
                            <input
                                type="text"
                                id="firstName"
                                name="firstName"
                                value={formData.firstName}
                                onChange={handleChange}
                                required
                                placeholder="Enter your first name"
                                disabled={loading}
                            />
                        </div>
                        <div className="form-group">
                            <label htmlFor="lastName">Last Name</label>
                            <input
                                type="text"
                                id="lastName"
                                name="lastName"
                                value={formData.lastName}
                                onChange={handleChange}
                                required
                                placeholder="Enter your last name"
                                disabled={loading}
                            />
                        </div>
                        <div className="form-group">
                            <label htmlFor="mobileNumber">Mobile Number</label>
                            <input
                                type="tel"
                                id="mobileNumber"
                                name="mobileNumber"
                                value={formData.mobileNumber}
                                onChange={handleChange}
                                placeholder="Enter your mobile number"
                                disabled={loading}
                            />
                        </div>
                        <div className="form-group">
                            <label htmlFor="password">Password</label>
                            <input
                                type="password"
                                id="password"
                                name="password"
                                value={formData.password}
                                onChange={handleChange}
                                required
                                placeholder="Enter your password"
                                disabled={loading}
                            />
                        </div>
                        <div className="form-group">
                            <label htmlFor="confirmPassword">Confirm Password</label>
                            <input
                                type="password"
                                id="confirmPassword"
                                name="confirmPassword"
                                value={formData.confirmPassword}
                                onChange={handleChange}
                                required
                                placeholder="Confirm your password"
                                disabled={loading}
                            />
                        </div>
                        <button className="auth-button" type="submit" disabled={loading}>
                            {loading ? 'Registering...' : 'Complete Registration'}
                        </button>
                    </form>
                )}

                <div className="auth-link">
                    Already have an account? <a href="/auth/login">Login</a>
                </div>
            </div>
        </div>
    );
};

export default Register; 