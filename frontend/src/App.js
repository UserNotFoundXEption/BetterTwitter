import React from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import Home from './components/Home'
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import ProtectedRoute from './components/ProtectedRoute';
import MessageDetails from './components/MessageDetails';
import LoginAttempts from './components/LoginAttempts';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
	<Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route
	  path="/dashboard"
	  element={
	    <ProtectedRoute>
	      <Dashboard />
	    </ProtectedRoute>
	  }
	/>
	<Route path="messages/verify/:messageId" element={<MessageDetails />} />
        <Route path="login-attempts" element={<LoginAttempts />} />
	<Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
}

export default App;

