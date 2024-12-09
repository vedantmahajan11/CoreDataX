import axios from 'axios';

const BASE_URL = 'http://localhost:5001';

export const loginUser = async (email, password) => {
  try {
    const response = await axios.post(`${BASE_URL}/login`, { email, password }, { withCredentials: true });
    if (response.data.success) {
      sessionStorage.setItem('user', JSON.stringify(response.data.user));
      return response.data;
    } else {
      return { success: false, message: response.data.message };
    }
  } catch (err) {
    console.error('Login failed', err);
    return { success: false, message: 'Login failed. Please try again.' };
  }
};

export const checkAuthStatus = async () => {
  try {
    const response = await axios.get(`${BASE_URL}/check-auth`, { withCredentials: true });
    return response.data.success;
  } catch (err) {
    console.error('Error checking authentication', err);
    return false;
  }
};

export const logoutUser = async () => {
  try {
    const response = await axios.post(`${BASE_URL}/logout`, {}, { withCredentials: true });
    if (response.data.success) {
      sessionStorage.removeItem('user');
      return true;
    } else {
      return false;
    }
  } catch (err) {
    console.error('Logout failed', err);
    return false;
  }
};
