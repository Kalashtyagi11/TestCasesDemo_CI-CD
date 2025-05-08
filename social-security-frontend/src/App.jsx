import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material';
import Login from './pages/auth/Login';
import Registration from './pages/auth/Register';
import ForgotPassword from './pages/auth/ForgotPassword';
import ChangePassword from './pages/auth/ChangePassword';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import CssBaseline from '@mui/material/CssBaseline';

const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
  typography: {
    button: {
      textTransform: 'none',
      fontWeight: 600,
    },
  },
  components: {
    MuiTextField: {
      defaultProps: {
        variant: 'outlined',
        size: 'medium',
      },
    },
    MuiButton: {
      defaultProps: {
        size: 'large',
      },
      styleOverrides: {
        root: {
          borderRadius: 8,
          padding: '10px 22px',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          borderRadius: 12,
        },
      },
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <BrowserRouter>
        <ToastContainer position="top-right" autoClose={5000} />
        <Routes>
          <Route path="/auth/login" element={<Login />} />
          <Route path="/auth/register" element={<Registration/>} />
          <Route path="/auth/forgot-password" element={<ForgotPassword />} />
          <Route path="/auth/change-password" element={<ChangePassword />} />
          <Route path="/" element={<Navigate to="/auth/register" replace />} />
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
