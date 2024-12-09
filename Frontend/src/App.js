import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Register from './components/Register';
import Login from './components/Login';
import DailyLog from './components/DailyLog';
import Leaderboard from './components/Leaderboard';
import UserDashboard from './components/UserDashboard';
import MentalHealthAssessment from './components/MentalHealthAssessment';
import FindFriends from './components/FindFriends';
import FriendProfile from './components/FriendProfile';


function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/daily-log" element={<DailyLog />} />
        <Route path="/mentalhealthassessment" element={<MentalHealthAssessment />} />
        <Route path="/leaderboard" element={<Leaderboard />} />
        <Route path="/user-dashboard" element={<UserDashboard />} /> 
        <Route path="/find-friends" element={<FindFriends />} />
      <Route path="/friend-profile/:user_id" element={<FriendProfile />} />
      </Routes>
    </Router>
  );
}

export default App;
