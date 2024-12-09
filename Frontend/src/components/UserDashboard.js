import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Container, Typography, Box, CircularProgress, Grid, Paper, Alert, Card, CardContent, CardActions, Button, TextField } from '@mui/material';
import { styled } from '@mui/system';
import { AccessTime, FitnessCenter, EmojiEmotions } from '@mui/icons-material';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import UpdateLog from './UpdateLog'; // Import UpdateLog component for updating logs
import DeleteLog from './DeleteLog'; // Import DeleteLog component for deleting logs

const UserDashboard = () => {
  const [userData, setUserData] = useState({
    total_rewards: 0,
    recommendations: [],
    logs: []
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null); // To store selected log for update
  const [searchKeyword, setSearchKeyword] = useState(''); // State for search input
  const [filteredLogs, setFilteredLogs] = useState([]); // State for filtered logs

  useEffect(() => {
    // Fetch user dashboard data when the component is mounted
    const fetchUserDashboard = async () => {
      try {
        const response = await axios.get('http://localhost:5001/user_dashboard', { withCredentials: true });

        if (response.status === 200) {
          setUserData(response.data);  // Set the data to state
          setFilteredLogs(response.data.logs); // Set initial logs to filteredLogs
        } else {
          setError('Failed to fetch data. Please try again later.');
        }
      } catch (err) {
        setError('Error fetching data. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    fetchUserDashboard();
  }, []);

  useEffect(() => {
    // Filter logs based on search keyword
    if (searchKeyword.trim() === '') {
      setFilteredLogs(userData.logs);
    } else {
      const filtered = userData.logs.filter(log => 
        log.screen_time.toString().includes(searchKeyword) || 
        log.social_media_time.toString().includes(searchKeyword) ||
        log.gaming_time.toString().includes(searchKeyword) ||
        log.sleep_hours.toString().includes(searchKeyword) ||
        log.physical_activity_hours.toString().includes(searchKeyword)
      );
      setFilteredLogs(filtered);
    }
  }, [searchKeyword, userData.logs]);

  // Styled components for better UI
  const InfoCard = styled(Card)(({ theme }) => ({
    boxShadow: theme.shadows[3],
    borderRadius: '8px',
    marginBottom: '20px',
    padding: '20px',
    transition: 'transform 0.3s ease-in-out',
    '&:hover': {
      transform: 'scale(1.05)',
      boxShadow: theme.shadows[10],
    },
  }));

  const IconBox = styled(Box)(({ theme }) => ({
    backgroundColor: theme.palette.primary.main,
    borderRadius: '50%',
    padding: '10px',
    display: 'inline-block',
    marginRight: '10px',
  }));

  // Function to refresh the dashboard data after update or delete
  const refreshDashboardData = async () => {
    const response = await axios.get('http://localhost:5001/user_dashboard', { withCredentials: true });
    if (response.status === 200) {
      setUserData(response.data);  // Set the updated data to state
      setFilteredLogs(response.data.logs); // Set updated logs to filteredLogs
    }
  };

  // Prepare data for graphs
  const chartData = userData.logs.map(log => ({
    date: new Date(log.date).toLocaleDateString(),
    screen_time: log.screen_time,
    social_media_time: log.social_media_time,
    gaming_time: log.gaming_time,
    sleep_hours: log.sleep_hours,
    physical_activity_hours: log.physical_activity_hours
  }));

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom align="center">
        User Dashboard
      </Typography>

      {error && <Alert severity="error">{error}</Alert>}
      {loading ? (
        <CircularProgress sx={{ display: 'block', margin: '50px auto' }} />
      ) : (
        <Box sx={{ mt: 3 }}>
          {/* **Search Input for Logs** */}
          <TextField
            label="Search Logs"
            variant="outlined"
            fullWidth
            value={searchKeyword}
            onChange={(e) => setSearchKeyword(e.target.value)}
            sx={{ mb: 3 }}
          />

          {/* **Total Rewards Card** */}
          <InfoCard>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                <IconBox>
                  <FitnessCenter sx={{ color: 'white' }} />
                </IconBox>
                Total Rewards
              </Typography>
              <Typography variant="h6" color="textSecondary">
                {userData.total_rewards} Points
              </Typography>
            </CardContent>
          </InfoCard>

          {/* **Recommendations Card** */}
          <InfoCard>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                <IconBox>
                  <EmojiEmotions sx={{ color: 'white' }} />
                </IconBox>
                Recommendations
              </Typography>
              {userData.recommendations.length === 0 ? (
                <Typography>No recommendations available.</Typography>
              ) : (
                userData.recommendations.map((rec, index) => (
                  <Box key={index} sx={{ mb: 2 }}>
                    <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                      {rec.content}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Date: {new Date(rec.date).toLocaleDateString()}
                    </Typography>
                  </Box>
                ))
              )}
            </CardContent>
          </InfoCard>

          {/* **User Logs Card** */}
          <InfoCard>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                <IconBox>
                  <AccessTime sx={{ color: 'white' }} />
                </IconBox>
                Your Daily Logs
              </Typography>
              {filteredLogs.length === 0 ? (
                <Typography>No logs available.</Typography>
              ) : (
                <Grid container spacing={3}>
                  {filteredLogs.map((log, index) => (
                    <Grid item xs={12} sm={6} key={index}>
                      <Paper sx={{ p: 3 }}>
                        <Typography variant="body1">Date: {new Date(log.date).toLocaleDateString()}</Typography>
                        <Typography variant="body2">Screen Time: {log.screen_time} hrs</Typography>
                        <Typography variant="body2">Social Media: {log.social_media_time} hrs</Typography>
                        <Typography variant="body2">Gaming: {log.gaming_time} hrs</Typography>
                        <Typography variant="body2">Sleep: {log.sleep_hours} hrs</Typography>
                        <Typography variant="body2">Physical Activity: {log.physical_activity_hours} hrs</Typography>
                        <Typography variant="body2">Stress Level: {log.stress_level}</Typography>
                        <Typography variant="body2">Mental Health: {log.mental_health_status}</Typography>

                        {/* Update and Delete buttons */}
                        <CardActions sx={{ justifyContent: 'space-between' }}>
                          <Button 
                            variant="outlined" 
                            color="primary"
                            onClick={() => setSelectedLog(log)} // Set selected log for update
                          >
                            Update
                          </Button>
                          <DeleteLog log_id={log.log_id} onDelete={refreshDashboardData} /> {/* Delete log button */}
                        </CardActions>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              )}
            </CardContent>
          </InfoCard>

          {/* **Update Log Modal (Optional) */}
          {selectedLog && <UpdateLog log={selectedLog} setSelectedLog={setSelectedLog} onUpdate={refreshDashboardData} />}

          {/* **Graph: Screen Time, Sleep, Gaming, etc. */}
          <Box sx={{ mt: 5 }}>
            <Typography variant="h5" gutterBottom>
              Activity Overview
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="screen_time" fill="#8884d8" />
                <Bar dataKey="social_media_time" fill="#82ca9d" />
                <Bar dataKey="gaming_time" fill="#ffc658" />
                <Bar dataKey="sleep_hours" fill="#ff8042" />
              </BarChart>
            </ResponsiveContainer>
          </Box>
        </Box>
      )}
    </Container>
  );
};

export default UserDashboard;
