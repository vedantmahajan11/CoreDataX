import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { Container, Grid, Typography, Button, Box, Paper, CircularProgress } from '@mui/material';

const Dashboard = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true); // Loading state to display loader while verifying user

  useEffect(() => {
    const checkAuthentication = async () => {
      try {
        // Attempt to get user data from sessionStorage
        const userData = JSON.parse(sessionStorage.getItem('userData'));

        if (!userData) {
          // No user data in sessionStorage, redirect to login
          navigate('/login');
        } else {
          // Set the user data from sessionStorage
          setUser(userData);
        }
      } catch (error) {
        console.error('Error retrieving user data from sessionStorage:', error);
        navigate('/login'); // Redirect to login on error
      } finally {
        setLoading(false); // Authentication check is complete
      }
    };

    checkAuthentication();
  }, [navigate]);

  if (loading) {
    return <CircularProgress style={{ display: 'block', margin: '50px auto' }} />;
  }

  return (
    <Container maxWidth="md" style={{ marginTop: '50px' }}>
      <Typography variant="h4" gutterBottom align="center">
        Welcome, {user?.username ? user.username : 'User'}!
      </Typography>

      <Grid container spacing={3} justifyContent="center">
        
        {/* **Daily Log Card** */}
        <Grid item xs={12} md={6}>
          <Paper elevation={3}>
            <Box p={3} textAlign="center">
              <Typography variant="h6" gutterBottom>Log Your Daily Data</Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Track your daily screen time, sleep hours, gaming time, and more to better understand your mental well-being.
              </Typography>
              <Button 
                variant="contained" 
                color="primary" 
                onClick={() => navigate('/daily-log')} 
                style={{ marginTop: '10px' }}
              >
                Log Daily Data
              </Button>
            </Box>
          </Paper>
        </Grid>

        {/* **Survey Card** */}
        <Grid item xs={12} md={6}>
          <Paper elevation={3}>
            <Box p={3} textAlign="center">
              <Typography variant="h6" gutterBottom>Take a Mental Health Survey</Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Assess your mental health through personalized surveys tailored to your needs and track progress over time.
              </Typography>
              <Button 
                variant="contained" 
                color="secondary" 
                onClick={() => navigate('/mentalhealthassessment')} 
                style={{ marginTop: '10px' }}
              >
                Take Survey
              </Button>
            </Box>
          </Paper>
        </Grid>

        {/* **Leaderboard Card** */}
        <Grid item xs={12} md={6}>
          <Paper elevation={3}>
            <Box p={3} textAlign="center">
              <Typography variant="h6" gutterBottom>Leaderboard</Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Check out where you stand among your peers. See how others are doing and get inspired.
              </Typography>
              <Button 
                variant="contained" 
                color="secondary" 
                onClick={() => navigate('/leaderboard')} 
                style={{ marginTop: '10px' }}
              >
                View Leaderboard
              </Button>
            </Box>
          </Paper>
        </Grid>

        {/* **User Dashboard Card** */}
        <Grid item xs={12} md={6}>
          <Paper elevation={3}>
            <Box p={3} textAlign="center">
              <Typography variant="h6" gutterBottom>View Your Dashboard</Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                View your rewards, recommendations, and logs all in one place.
              </Typography>
              <Button 
                variant="contained" 
                color="primary" 
                onClick={() => navigate('/user-dashboard')} 
                style={{ marginTop: '10px' }}
              >
                Go to Dashboard
              </Button>
            </Box>
          </Paper>
        </Grid>

        {/* **Find Friends Card** */}
        <Grid item xs={12} md={6}>
          <Paper elevation={3}>
            <Box p={3} textAlign="center">
              <Typography variant="h6" gutterBottom>Find Friends</Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                Connect with your friends and view their progress.
              </Typography>
              <Button 
                variant="contained" 
                color="primary" 
                onClick={() => navigate('/find-friends')} 
                style={{ marginTop: '10px' }}
              >
                Find Friends
              </Button>
            </Box>
          </Paper>
        </Grid>

      </Grid>
    </Container>
  );
};

export default Dashboard;
