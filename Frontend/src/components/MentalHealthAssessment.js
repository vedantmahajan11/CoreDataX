import React, { useState } from 'react';
import axios from 'axios';
import { Container, Typography, TextField, Button, Box, CircularProgress, Alert } from '@mui/material';

const MentalHealthAssessment = () => {
  const [formData, setFormData] = useState({
    sleep: '',
    appetite: '',
    interest: '',
    fatigue: '',
    worthlessness: '',
    concentration: '',
    agitation: '',
    suicidal_ideation: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post(
        'http://localhost:5001/mental_health_assessment',
        formData,
        { withCredentials: true }
      );

      if (response.data.success) {
        setSuccessMessage('Assessment submitted successfully!');
        setError(null);
      } else {
        setError('Failed to submit assessment. Please try again later.');
        setSuccessMessage(null);
      }
    } catch (err) {
      setError('Error submitting assessment. Please try again later.');
      setSuccessMessage(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="sm" style={{ marginTop: '50px' }}>
      <Typography variant="h4" gutterBottom align="center">
        Mental Health Assessment
      </Typography>

      {/* Display success message */}
      {successMessage && <Alert severity="success" sx={{ mb: 2 }}>{successMessage}</Alert>}

      {/* Display error message */}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {/* Assessment Form */}
      <form onSubmit={handleSubmit}>
        <TextField
          label="Sleep (1-10)"
          name="sleep"
          value={formData.sleep}
          onChange={handleChange}
          fullWidth
          required
          type="number"
          inputProps={{ min: 1, max: 10 }}
          variant="outlined"
          sx={{ mb: 2 }}
        />
        <TextField
          label="Appetite (1-10)"
          name="appetite"
          value={formData.appetite}
          onChange={handleChange}
          fullWidth
          required
          type="number"
          inputProps={{ min: 1, max: 10 }}
          variant="outlined"
          sx={{ mb: 2 }}
        />
        <TextField
          label="Interest (1-10)"
          name="interest"
          value={formData.interest}
          onChange={handleChange}
          fullWidth
          required
          type="number"
          inputProps={{ min: 1, max: 10 }}
          variant="outlined"
          sx={{ mb: 2 }}
        />
        <TextField
          label="Fatigue (1-10)"
          name="fatigue"
          value={formData.fatigue}
          onChange={handleChange}
          fullWidth
          required
          type="number"
          inputProps={{ min: 1, max: 10 }}
          variant="outlined"
          sx={{ mb: 2 }}
        />
        <TextField
          label="Worthlessness (1-10)"
          name="worthlessness"
          value={formData.worthlessness}
          onChange={handleChange}
          fullWidth
          required
          type="number"
          inputProps={{ min: 1, max: 10 }}
          variant="outlined"
          sx={{ mb: 2 }}
        />
        <TextField
          label="Concentration (1-10)"
          name="concentration"
          value={formData.concentration}
          onChange={handleChange}
          fullWidth
          required
          type="number"
          inputProps={{ min: 1, max: 10 }}
          variant="outlined"
          sx={{ mb: 2 }}
        />
        <TextField
          label="Agitation (1-10)"
          name="agitation"
          value={formData.agitation}
          onChange={handleChange}
          fullWidth
          required
          type="number"
          inputProps={{ min: 1, max: 10 }}
          variant="outlined"
          sx={{ mb: 2 }}
        />
        <TextField
          label="Suicidal Ideation (1-10)"
          name="suicidal_ideation"
          value={formData.suicidal_ideation}
          onChange={handleChange}
          fullWidth
          required
          type="number"
          inputProps={{ min: 1, max: 10 }}
          variant="outlined"
          sx={{ mb: 2 }}
        />

        <Button
          variant="contained"
          color="primary"
          type="submit"
          fullWidth
          disabled={loading}
          sx={{ mt: 2 }}
        >
          {loading ? 'Submitting...' : 'Submit Assessment'}
        </Button>
      </form>
    </Container>
  );
};

export default MentalHealthAssessment;
