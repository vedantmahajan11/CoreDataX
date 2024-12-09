import React from 'react';
import { Button } from '@mui/material';
import axios from 'axios';

const DeleteLog = ({ log_id }) => {
  const handleDelete = async () => {
    try {
      const response = await axios.post('http://localhost:5001/delete_daily_log', { log_id }, { withCredentials: true });
      if (response.data.success) {
        alert('Log deleted successfully');
        window.location.reload(); // Optionally, reload the page to reflect the change
      } else {
        alert('Failed to delete log');
      }
    } catch (error) {
      alert('Error deleting log');
    }
  };

  return (
    <Button variant="outlined" color="error" onClick={handleDelete}>
      Delete
    </Button>
  );
};

export default DeleteLog;
