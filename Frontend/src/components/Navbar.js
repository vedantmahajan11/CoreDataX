import React, { useState, useEffect } from 'react';
import { AppBar, Toolbar, Typography, Button, Box, Menu, MenuItem, IconButton } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import MenuIcon from '@mui/icons-material/Menu';

const Navbar = () => {
  const [user, setUser] = useState(null); // State to store user information
  const [anchorEl, setAnchorEl] = useState(null); // State for the dropdown menu
  const navigate = useNavigate();

  // Run only once when the component mounts to get user data from sessionStorage
  useEffect(() => {
    const userData = sessionStorage.getItem('userData');
    if (userData) {
      setUser(JSON.parse(userData)); // Parse and set user data
    }
  }, []); // Empty dependency array ensures this runs only once

  // Handle Menu open
  const handleMenuOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  // Handle Menu close
  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  // Handle Logout
  const handleLogout = () => {
    sessionStorage.removeItem('userData'); // Clear user data from sessionStorage
    setUser(null); // Set user to null
    navigate('/login'); // Redirect to login page
  };

  return (
    <AppBar position="sticky" color="primary">
      <Toolbar>
        
        {/* Mobile Menu Icon */}
        <IconButton 
          edge="start" 
          color="inherit" 
          aria-label="menu" 
          onClick={handleMenuOpen} 
          sx={{ display: { xs: 'block', sm: 'none' } }}
        >
          <MenuIcon />
        </IconButton>

        {/* Main Logo/Title */}
        <Typography 
          variant="h6" 
          sx={{ flexGrow: 1, cursor: 'pointer' }} 
          onClick={() => navigate('/dashboard')}
        >
          Mental Health Tracker
        </Typography>

        {/* Desktop User Menu */}
        {user ? (
          <Box display="flex" alignItems="center">
            <Typography variant="body1" sx={{ marginRight: '20px' }}>
              Welcome, {user?.username || 'User'}
            </Typography>
            <Button 
              color="inherit" 
              onClick={handleLogout}
            >
              Logout
            </Button>
          </Box>
        ) : (
          <Button color="inherit" onClick={() => navigate('/login')}>Login</Button>
        )}

        {/* Mobile User Menu */}
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleMenuClose}
        >
          {user ? (
            <>
              <MenuItem onClick={handleMenuClose}>
                Welcome, {user?.username || 'User'}
              </MenuItem>
              <MenuItem onClick={handleLogout}>Logout</MenuItem>
            </>
          ) : (
            <MenuItem onClick={() => navigate('/login')}>Login</MenuItem>
          )}
        </Menu>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;
