import axios from 'axios';

const API_URL = 'http://localhost:7068/api/auth';

const authService = {
    // Initiate registration and send verification code
    initiateRegistration: async (email) => {
        debugger
        try {
            const response = await axios.post(`${API_URL}/initiate-registration`, { email });
            return response.data;
        } catch (error) {
            throw error.response?.data || error.message;
        }
    },

    // Verify registration code and complete registration
    verifyAndCompleteRegistration: async (registerData) => {
        try {
            const response = await axios.post(`${API_URL}/verify-and-complete-registration`, registerData);
            return response.data;
        } catch (error) {
            throw error.response?.data || error.message;
        }
    },

    // Login
    login: async (loginData) => {
        debugger
        try {
            const response = await axios.post(`${API_URL}/login`, loginData);
            return response.data;
        } catch (error) {
            throw error.response?.data || error.message;
        }
    },

    // Password management
    forgotPassword: async (email) => {
        try {
            const response = await axios.post(`${API_URL}/forgot-password`, { email });
            return response.data;
        } catch (error) {
            throw error.response?.data || error.message;
        }
    },

    resetPassword: async (token, newPassword) => {
        try {
            const response = await axios.post(`${API_URL}/reset-password`, { 
                resetToken: token, 
                newPassword 
            });
            return response.data;
        } catch (error) {
            throw error.response?.data || error.message;
        }
    },

    changePassword: async (currentPassword, newPassword) => {
        try {
            const token = localStorage.getItem('token');
            const response = await axios.post(`${API_URL}/change-password`, 
                { currentPassword, newPassword },
                { headers: { Authorization: `Bearer ${token}` } }
            );
            return response.data;
        } catch (error) {
            throw error.response?.data || error.message;
        }
    },

    // User management
    getCurrentUser: () => {
        const user = localStorage.getItem('user');
        return user ? JSON.parse(user) : null;
    },

    isAuthenticated: () => {
        return !!localStorage.getItem('token');
    },

    logout: () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
    }
};

export default authService; 