import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { TextField, Button, Container, Typography, Link, Paper, Alert, CircularProgress } from '@mui/material';
import { useNavigate } from 'react-router-dom';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // Check if user is already logged in
  useEffect(() => {
    const userData = sessionStorage.getItem('userData');
    if (userData) {
      console.log('User already logged in. Redirecting to dashboard...');
      navigate('/dashboard'); // Redirect to dashboard if user is already logged in
    }
  }, [navigate]);

  // Handle Login Function
  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true); // Start loading
    setError(''); // Clear previous errors

    try {
      // Send login request to the server
      const response = await axios.post(
        'http://localhost:5001/login',
        { email, password },
        { withCredentials: true } // To send and receive cookies/sessions
      );

      if (response.data.success) {
        // Save user data in sessionStorage if login is successful
        const userData = response.data; 
        sessionStorage.setItem('userData', JSON.stringify(userData));
        console.log('Login successful! User Data:', userData);
        
        // Navigate after slight delay to ensure session data is properly set
        setTimeout(() => {
          navigate('/dashboard');
        }, 500); 
      } else {
        setError(response.data.message || 'Invalid credentials. Please try again.');
      }
    } catch (err) {
      console.error('Error during login:', err);
      setError('Unable to connect to the server. Please try again later.');
    } finally {
      setLoading(false); // Stop loading
    }
  };

  return (
    <Container maxWidth="sm" sx={{ mt: 8 }}>
      <Paper elevation={3} sx={{ p: 4, borderRadius: '16px' }}>
        <Typography variant="h4" gutterBottom align="center">
          Login
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleLogin}>
          <TextField
            label="Email"
            type="email"
            fullWidth
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            sx={{ mb: 3 }}
            variant="outlined"
          />
          <TextField
            label="Password"
            type="password"
            fullWidth
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            sx={{ mb: 3 }}
            variant="outlined"
          />
          
          <Button
            type="submit"
            variant="contained"
            color="primary"
            fullWidth
            sx={{ mt: 2, py: 1.5 }}
            disabled={loading}
          >
            {loading ? <CircularProgress size={24} sx={{ color: 'white' }} /> : 'Log In'}
          </Button>

          <Typography variant="body2" align="center" sx={{ mt: 3 }}>
            Don't have an account?{' '}
            <Link
              href="#"
              onClick={() => navigate('/register')}
              sx={{ ml: 1, cursor: 'pointer' }}
            >
              Register here
            </Link>
          </Typography>
        </form>
      </Paper>
    </Container>
  );
};

export default Login;
