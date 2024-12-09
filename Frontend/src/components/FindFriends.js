import React, { useState } from 'react';
import axios from 'axios';
import { Container, TextField, Button, Typography, Box, CircularProgress, Alert, Paper } from '@mui/material';

const FindFriends = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [friends, setFriends] = useState([]);

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      setError('Please enter a username to search');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await axios.get(`http://localhost:5001/find_friends?query=${searchQuery}`, { withCredentials: true });

      if (response.status === 200 && response.data.success) {
        setFriends(response.data.users);
      } else {
        setError(response.data.message || 'Failed to search for friends');
      }
    } catch (error) {
      setError('Error searching for friends. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom align="center">
        Find Friends
      </Typography>

      {error && <Alert severity="error">{error}</Alert>}

      <Box sx={{ mt: 3 }}>
        <TextField
          label="Search by Username"
          variant="outlined"
          fullWidth
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          sx={{ mb: 2 }}
        />

        <Button
          variant="contained"
          color="primary"
          onClick={handleSearch}
          disabled={loading}
        >
          {loading ? 'Searching...' : 'Search'}
        </Button>
      </Box>

      {friends.length > 0 && (
        <Box sx={{ mt: 3 }}>
          <Typography variant="h6" gutterBottom>
            Search Results:
          </Typography>

          {friends.map((friend) => (
            <Paper key={friend.user_id} sx={{ p: 2, mb: 2 }}>
              <Typography variant="body1">Username: {friend.username}</Typography>
              <Typography variant="body2">Total Rewards: {friend.total_rewards || 'No Rewards'}</Typography>
              <Button 
                variant="outlined" 
                color="primary" 
                onClick={() => window.location.href = `/friend-profile/${friend.user_id}`}
              >
                View Profile
              </Button>
            </Paper>
          ))}
        </Box>
      )}
    </Container>
  );
};

export default FindFriends;
