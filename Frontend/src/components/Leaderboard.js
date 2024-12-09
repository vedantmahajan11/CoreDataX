import React, { useState, useEffect } from 'react';
import Navbar from './Navbar'; 
import { Container, Typography, Box, CircularProgress, Grid, Paper, Avatar } from '@mui/material';
import axios from 'axios';
import { styled } from '@mui/system';

// Styled components for modern look and animations
const LeaderboardContainer = styled(Container)(({ theme }) => ({
  marginTop: '50px',
  textAlign: 'center',
}));

const LeaderboardTitle = styled(Typography)(({ theme }) => ({
  fontSize: '2rem',
  fontWeight: 'bold',
  color: theme.palette.primary.main,
  marginBottom: '20px',
}));

const LeaderboardCard = styled(Paper)(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  padding: theme.spacing(2),
  borderRadius: '16px',
  background: 'linear-gradient(145deg, #e6e6e6, #ffffff)',
  boxShadow: '10px 10px 20px #d9d9d9, -10px -10px 20px #ffffff',
  transition: 'transform 0.2s ease-in-out',
  '&:hover': {
    transform: 'scale(1.02)',
    boxShadow: '0px 8px 24px rgba(0,0,0,0.1)',
  },
}));

const RankBadge = styled(Box)(({ theme }) => ({
  width: '50px',
  height: '50px',
  borderRadius: '50%',
  backgroundColor: theme.palette.primary.main,
  color: '#fff',
  fontSize: '18px',
  fontWeight: 'bold',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  marginRight: '20px',
  boxShadow: '0px 4px 8px rgba(0, 0, 0, 0.2)',
}));

const UserInfo = styled(Box)(({ theme }) => ({
  display: 'flex',
  flexDirection: 'column',
}));

const UserName = styled(Typography)(({ theme }) => ({
  fontSize: '1.2rem',
  fontWeight: 'bold',
  color: '#333',
}));

const UserStats = styled(Typography)(({ theme }) => ({
  fontSize: '0.9rem',
  color: theme.palette.text.secondary,
}));

const AvatarContainer = styled(Avatar)(({ theme }) => ({
  width: '50px',
  height: '50px',
  marginRight: '15px',
  backgroundColor: theme.palette.primary.main,
  fontSize: '20px',
  fontWeight: 'bold',
}));

const Leaderboard = () => {
  const [leaderboardData, setLeaderboardData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchLeaderboard();
  }, []);

  const fetchLeaderboard = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('http://localhost:5001/leaderboard');
      setLeaderboardData(response.data);
    } catch (err) {
      setError('Error fetching leaderboard data. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Navbar />
      <LeaderboardContainer maxWidth="md">
        <LeaderboardTitle variant="h4">
          🏆 User Leaderboard 🏆
        </LeaderboardTitle>

        {loading && <CircularProgress size={40} style={{ display: 'block', margin: 'auto', marginTop: '20px' }} />}

        {error && !loading && (
          <Typography color="error" align="center" style={{ marginTop: '20px' }}>
            {error}
          </Typography>
        )}

        {!loading && !error && leaderboardData.length === 0 && (
          <Typography align="center" style={{ marginTop: '20px' }}>
            No leaderboard data available.
          </Typography>
        )}

        <Grid container spacing={3} justifyContent="center">
          {leaderboardData.map((user, index) => (
            <Grid item xs={12} key={user.user_id}>
              <LeaderboardCard 
                style={user.is_current_user ? { backgroundColor: '#e0f7fa' } : {}}
              >
                <RankBadge>
                  #{index + 1}
                </RankBadge>

                <AvatarContainer>
                  {user.username ? user.username.charAt(0).toUpperCase() : '?'}
                </AvatarContainer>

                <UserInfo>
                  <UserName>{user.username}</UserName>
                  <UserStats>Total Physical Activity: {user.total_physical_activity} hours</UserStats>
                  <UserStats>Total Rewards: {user.total_rewards} points</UserStats>
                </UserInfo>
              </LeaderboardCard>
            </Grid>
          ))}
        </Grid>
      </LeaderboardContainer>
    </>
  );
};

export default Leaderboard;
