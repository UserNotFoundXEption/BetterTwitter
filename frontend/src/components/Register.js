import React, { useState } from 'react';
import { Link } from 'react-router-dom';
const Register = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [qrCode, setQrCode] = useState(null);
  const [step, setStep] = useState(1);
  const [confirmationLink, setConfirmationLink] = useState("");

  const handleRegister = async (e) => {
    e.preventDefault();
    
    const response = await fetch('https://127.0.0.1/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    });

    const data = await response.json();
    if (response.ok) {
      setQrCode(data.qr_code);
      setMessage(data.message);
      setStep(2);
    } else {
      setMessage(data.error || 'Registration failed.');
    }
  };

  const handleVerifyTotp = async (e) => {
    e.preventDefault();

    const totpCode = prompt('Enter the code from your authernticator app:');
    const response = await fetch('https://127.0.0.1/register/verify-totp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, totp_code: totpCode }),
    });

    const data = await response.json();
    if (response.ok) {
      setMessage(data.message);
      setConfirmationLink("http://127.0.0.1:3000" + data.link);
    } else {
      setMessage(data.error || 'Verification failed.');
    }
  };


  return (
    <div>
      <h2>Register</h2>
      {step === 1 && (
        <form onSubmit={handleRegister}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
	  <input
	    type="text"
	    placeholder="Email"
	    value={email}
	    onChange={(e) => setEmail(e.target.value)}
	  />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button type="submit">Register</button>
        </form>
      )}
      {step === 2 && (
        <div>
          <h2>Scan QR Code</h2>
          {qrCode && <img src={`data:image/png;base64,${qrCode}`} alt="Scan QR Code" />}
          <button onClick={handleVerifyTotp}>Verify TOTP</button>
        </div>
      )}
      {message && <p>{message}</p>}
      <a href={confirmationLink}>{confirmationLink}</a>
      <p>
        Already an awesome member? <Link to="/login">Login here</Link>
      </p>
      <p>
        Back to <Link to="/">Home page</Link>
      </p>
    </div>
  );
};

export default Register;

