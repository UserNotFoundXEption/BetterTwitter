import React, { useState, useEffect } from "react";

const LoginAttempts = () => {
  const [loginAttempts, setLoginAttempts] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchLoginAttempts = async () => {
      try {
        const response = await fetch(`http://127.0.0.1:5000/login-attempts`, {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        });

        if (!response.ok) {
	  console.log(response);
          throw new Error(`${response.status} - ${response.statusText}`);
        }

        const data = await response.json();
        setLoginAttempts(data.login_attempts);
        setLoading(false);
      } catch (err) {
        setError(err.message);
        setLoading(false);
      }
    };

    fetchLoginAttempts();
  });

  if (loading) {
    return <div>Loading...</div>;
  }

  if (error) {
    return <div>Error: {error}</div>;
  }

  return (
    <div>
      <h1>Login Attempts</h1>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>IP Address</th>
            <th>Successful</th>
          </tr>
        </thead>
        <tbody>
          {loginAttempts.map((attempt, index) => (
            <tr key={index}>
              <td>{new Date(attempt.time).toLocaleString()}</td>
              <td>{attempt.ip}</td>
              <td>{attempt.successful ? "Yes" : "No"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default LoginAttempts;

