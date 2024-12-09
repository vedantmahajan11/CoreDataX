import React from 'react';
import ReactDOM from 'react-dom/client';
import { ThemeProvider, createTheme } from '@mui/material/styles';  // Import ThemeProvider and createTheme
import App from './App';

// Define a custom theme (you can customize it further)
const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2', // Blue
    },
    secondary: {
      main: '#d32f2f', // Red
    },
    background: {
      paper: '#ffffff', // This is for the 'paper' background color
    },
  },
});

// Create the root and render the app wrapped in ThemeProvider
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <ThemeProvider theme={theme}>  {/* Wrap your App in ThemeProvider */}
    <App />
  </ThemeProvider>
);
