import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [ip, setIp] = useState(''); 
  
  useEffect(() => {
    const fetchPublicIp = async () => {
      try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        setIp(data.ip);
      } catch (error) {
        console.error('Failed to fetch public IP:', error);
      }
    };
    
    fetchPublicIp();
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    const response = await fetch('https://127.0.0.1/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, totpCode, ip }),
    });
    
    const data = await response.json();
    if (response.ok) {
      localStorage.setItem('token', data.token); 
      setMessage('Login successful!');
      window.location.href = '/dashboard'; 
    } else {
      setMessage(data.error || 'Login failed.');
    }
  };

  return (
    <div>
      <h2>Login</h2>
      <form onSubmit={handleLogin}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
	<input
	  type="text"
	  placeholder="2FA code"
	  value={totpCode}
	  onChange={(e) => setTotpCode(e.target.value)}
	/>
        <button type="submit">Login</button>
      </form>
      {message && <p>{message}</p>}
      <p>
	  No account yet? <Link to="/register">Register here or die</Link>
      </p>
      <p>
	  <Link to="/request-password-reset">Forgot password?</Link>
      </p>
      <p>
	  Back to <Link to="/">Home page</Link>
      </p>
    </div>
  );
};

export default Login;

