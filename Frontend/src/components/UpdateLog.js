import React, { useState } from 'react';
import { TextField, Button, Dialog, DialogActions, DialogContent, DialogTitle, Grid } from '@mui/material';
import axios from 'axios';

const UpdateLog = ({ log, setSelectedLog }) => {
  const [formData, setFormData] = useState({
    screen_time: log.screen_time,
    social_media_time: log.social_media_time,
    gaming_time: log.gaming_time,
    sleep_hours: log.sleep_hours,
    physical_activity_hours: log.physical_activity_hours,
  });

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:5001/update_daily_log', { ...formData, log_id: log.log_id }, { withCredentials: true });
      if (response.data.success) {
        alert('Log updated successfully!');
        setSelectedLog(null); // Close the update form
      } else {
        alert('Failed to update the log');
      }
    } catch (error) {
      alert('Error updating log');
    }
  };

  return (
    <Dialog open={Boolean(log)} onClose={() => setSelectedLog(null)}>
      <DialogTitle>Update Daily Log</DialogTitle>
      <DialogContent>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Screen Time (hrs)"
              name="screen_time"
              value={formData.screen_time}
              onChange={handleChange}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Social Media Time (hrs)"
              name="social_media_time"
              value={formData.social_media_time}
              onChange={handleChange}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Gaming Time (hrs)"
              name="gaming_time"
              value={formData.gaming_time}
              onChange={handleChange}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Sleep Hours"
              name="sleep_hours"
              value={formData.sleep_hours}
              onChange={handleChange}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Physical Activity Hours"
              name="physical_activity_hours"
              value={formData.physical_activity_hours}
              onChange={handleChange}
              fullWidth
            />
          </Grid> 
        </Grid>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => setSelectedLog(null)} color="secondary">
          Cancel
        </Button>
        <Button onClick={handleSubmit} color="primary">
          Save Changes
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default UpdateLog;
