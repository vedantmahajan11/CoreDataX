import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import { Container, Typography, Box, CircularProgress, Alert, Paper } from '@mui/material';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const FriendProfile = () => {
  const { user_id } = useParams();
  const [progress, setProgress] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchFriendProgress = async () => {
      try {
        const response = await axios.get(`http://localhost:5001/friend_progress/${user_id}`, { withCredentials: true });

        if (response.status === 200 && response.data.success) {
          setProgress(response.data.progress);
        } else {
          setError(response.data.message || 'Failed to fetch friend progress');
        }
      } catch (error) {
        setError('Error fetching progress. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    fetchFriendProgress();
  }, [user_id]);

  const chartData = progress.map(item => ({
    date: new Date(item.date).toLocaleDateString(),
    screen_time: item.screen_time,
    sleep_hours: item.sleep_hours,
    physical_activity_hours: item.physical_activity_hours
  }));

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom align="center">
        Friend's Progress
      </Typography>

      {error && <Alert severity="error">{error}</Alert>}

      {loading ? (
        <CircularProgress sx={{ display: 'block', margin: '50px auto' }} />
      ) : (
        <Box sx={{ mt: 3 }}>
          {progress.length === 0 ? (
            <Typography>No progress data available.</Typography>
          ) : (
            <>
              <Typography variant="h6" gutterBottom>
                Activity Overview
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="screen_time" fill="#8884d8" />
                  <Bar dataKey="sleep_hours" fill="#82ca9d" />
                  <Bar dataKey="physical_activity_hours" fill="#ffc658" />
                </BarChart>
              </ResponsiveContainer>
            </>
          )}
        </Box>
      )}
    </Container>
  );
};

export default FriendProfile;
