import React, { useState, useEffect } from 'react';
import Navbar from './Navbar'; 
import axios from 'axios';
import {
  Container,
  TextField,
  Button,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Box,
  CircularProgress,
  Alert,
  Grid
} from '@mui/material';

const DailyLog = () => {
  const [logs, setLogs] = useState([]);
  const [form, setForm] = useState({
    screen_time: '',
    social_media_time: '',
    gaming_time: '',
    sleep_hours: '',
    physical_activity_hours: ''
  });

  const [loading, setLoading] = useState(false); 
  const [error, setError] = useState(null); 
  const [formError, setFormError] = useState(null); 

  const backendURL = 'http://localhost:5001'; 

  // Extract user_id from sessionStorage
  useEffect(() => {
    const userData = JSON.parse(sessionStorage.getItem('userData'));
    if (userData && userData.user_id) {
      fetchLogs(userData.user_id);
    } else {
      setError('User is not logged in. Please log in to access this page.');
    }
  }, []);

  // Fetch logs from the server
  const fetchLogs = async (user_id) => {
    setLoading(true);
    try {
      const response = await axios.get(`${backendURL}/daily_log`, { withCredentials: true });
      if (response.status === 200 && response.data.logs) {
        setLogs(response.data.logs);
        setError(null); 
      } else {
        setError('Failed to fetch logs. Please try again later.');
      }
    } catch (error) {
      console.error('Error fetching logs:', error);
      setError('Error fetching logs. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  // Handle form input changes
  const handleChange = (e) => {
    setForm({
      ...form,
      [e.target.name]: e.target.value,
    });
  };

  // Form validation logic
  const validateForm = () => {
    const { screen_time, social_media_time, gaming_time, sleep_hours, physical_activity_hours } = form;
    if (!screen_time || !social_media_time || !gaming_time || !sleep_hours || !physical_activity_hours) {
      return 'All fields are required';
    }
    if (isNaN(screen_time) || isNaN(social_media_time) || isNaN(gaming_time) || isNaN(sleep_hours) || isNaN(physical_activity_hours)) {
      return 'All fields must be numbers';
    }
    return null;
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();

    const validationError = validateForm();
    if (validationError) {
      setFormError(validationError);
      return;
    }

    const userData = JSON.parse(sessionStorage.getItem('userData'));
    const user_id = userData ? userData.user_id : null;

    if (!user_id) {
      setError('User is not logged in. Please log in to access this page.');
      return;
    }

    setLoading(true);
    try {
      const formData = {
        ...form,
        user_id: user_id, // Include user_id in the form data
      };

      const response = await axios.post(`${backendURL}/daily_log`, formData, { withCredentials: true });
      if (response.data.success) {
        fetchLogs(user_id); 
        setForm({
          screen_time: '',
          social_media_time: '',
          gaming_time: '',
          sleep_hours: '',
          physical_activity_hours: ''
        });
        setFormError(null); 
      } else {
        setError('Error submitting log. Please try again later.');
      }
    } catch (error) {
      console.error('Error submitting log:', error);
      setError('Error submitting log. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Navbar />
      <Container maxWidth="md" sx={{ mt: 4 }}>
        <Typography variant="h4" gutterBottom align="center">
          Log Your Daily Data
        </Typography>

        {formError && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {formError}
          </Alert>
        )}
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleSubmit}>
          <Paper elevation={3} sx={{ p: 3, mt: 3 }}>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <TextField
                  label="Screen Time (hrs)"
                  name="screen_time"
                  value={form.screen_time}
                  onChange={handleChange}
                  fullWidth
                  required
                  variant="outlined"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  label="Social Media Time (hrs)"
                  name="social_media_time"
                  value={form.social_media_time}
                  onChange={handleChange}
                  fullWidth
                  required
                  variant="outlined"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  label="Gaming Time (hrs)"
                  name="gaming_time"
                  value={form.gaming_time}
                  onChange={handleChange}
                  fullWidth
                  required
                  variant="outlined"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  label="Sleep Hours"
                  name="sleep_hours"
                  value={form.sleep_hours}
                  onChange={handleChange}
                  fullWidth
                  required
                  variant="outlined"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  label="Physical Activity Hours"
                  name="physical_activity_hours"
                  value={form.physical_activity_hours}
                  onChange={handleChange}
                  fullWidth
                  required
                  variant="outlined"
                />
              </Grid>
            </Grid>
            <Button variant="contained" color="primary" type="submit" fullWidth sx={{ mt: 2 }}>
              {loading ? 'Submitting...' : 'Submit Log'}
            </Button>
          </Paper>
        </form>

        <Box sx={{ mt: 3 }}>
          <Typography variant="h5" align="center">Your Logs</Typography>

          {loading ? (
            <CircularProgress sx={{ mt: 2 }} />
          ) : (
            <TableContainer component={Paper} sx={{ mt: 2 }}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Screen Time</TableCell>
                    <TableCell>Social Media</TableCell>
                    <TableCell>Gaming</TableCell>
                    <TableCell>Sleep Hours</TableCell>
                    <TableCell>Physical Activity</TableCell>
                    <TableCell>Stress Level</TableCell>
                    <TableCell>Mental Health Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {logs.map((log, index) => (
                    <TableRow key={index}>
                      <TableCell>{log.screen_time}</TableCell>
                      <TableCell>{log.social_media_time}</TableCell>
                      <TableCell>{log.gaming_time}</TableCell>
                      <TableCell>{log.sleep_hours}</TableCell>
                      <TableCell>{log.physical_activity_hours}</TableCell>
                      <TableCell>{log.stress_level}</TableCell>
                      <TableCell>{log.mental_health_status}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Box>
      </Container>
    </>
  );
};

export default DailyLog;
