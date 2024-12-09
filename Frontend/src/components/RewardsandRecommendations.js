import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Container, Typography, Box, CircularProgress, Grid, Card, CardContent, CardActions, Button } from '@mui/material';
import { makeStyles } from '@mui/styles';

const useStyles = makeStyles((theme) => ({
  root: {
    flexGrow: 1,
    marginTop: theme.spacing(4),
  },
  card: {
    maxWidth: 345,
    margin: theme.spacing(2),
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
    borderRadius: 8,
  },
  title: {
    fontWeight: 'bold',
    color: theme.palette.primary.main,
  },
  subtitle: {
    fontSize: '1rem',
    color: theme.palette.text.secondary,
  },
  recommendation: {
    marginTop: theme.spacing(2),
    padding: theme.spacing(1),
    backgroundColor: theme.palette.background.paper,
    borderRadius: 4,
  },
  button: {
    marginTop: theme.spacing(2),
  },
  errorMessage: {
    color: theme.palette.error.main,
    marginTop: theme.spacing(2),
  },
}));

const RewardsAndRecommendations = () => {
  const classes = useStyles();
  const [rewardsData, setRewardsData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchUserRewardsAndRecommendations();
  }, []);

  const fetchUserRewardsAndRecommendations = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('http://localhost:5001/getUserRewardsAndRecommendations');
      setRewardsData(response.data);
    } catch (err) {
      setError('Error fetching rewards and recommendations.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg" className={classes.root}>
      <Typography variant="h4" gutterBottom align="center">
        Your Rewards and Recommendations
      </Typography>

      {loading && <CircularProgress />}

      {error && <Typography className={classes.errorMessage} align="center">{error}</Typography>}

      {!loading && !error && rewardsData.length === 0 && (
        <Typography variant="h6" align="center" color="textSecondary">No data available.</Typography>
      )}

      <Grid container spacing={4} justifyContent="center">
        {rewardsData.map((user) => (
          <Grid item xs={12} sm={6} md={4} key={user.user_id}>
            <Card className={classes.card}>
              <CardContent>
                <Typography variant="h6" className={classes.title}>
                  {user.user_name}
                </Typography>
                <Typography className={classes.subtitle}>
                  Total Rewards: {user.total_rewards}
                </Typography>
                <Typography className={classes.subtitle}>
                  Total Physical Activity: {user.total_physical_activity} hours
                </Typography>
                <Typography className={classes.subtitle}>
                  Mental Health Status: {user.mental_health_status}
                </Typography>
                <Typography className={classes.subtitle}>
                  Average Stress Level: {user.avg_stress}
                </Typography>
              </CardContent>
              <CardActions>
                <Box className={classes.recommendation}>
                  <Typography variant="body2" color="textSecondary">
                    Recommendation: {user.recommendation}
                  </Typography>
                </Box>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Box display="flex" justifyContent="center" className={classes.button}>
        <Button variant="contained" color="primary" onClick={fetchUserRewardsAndRecommendations}>
          Refresh Data
        </Button>
      </Box>
    </Container>
  );
};

export default RewardsAndRecommendations;
