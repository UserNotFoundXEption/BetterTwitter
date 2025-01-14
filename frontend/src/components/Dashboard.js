import React, { useEffect, useState } from 'react';
import { useNavigate } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import "../styles/styles.css";

const Dashboard = () => {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    fetch('http://127.0.0.1:5000/messages')
      .then((response) => response.json())
      .then((data) => setMessages(data))
      .catch((error) => console.error('Error fetching messages:', error));
  }, []);

  const sendMessage = async () => {
    const token = localStorage.getItem('token');
    const response = await fetch('http://127.0.0.1:5000/messages/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ content: newMessage }),
    });

    if (response.ok) {
      const newMessageData = await response.json();
      setMessages([...messages, newMessageData]);
      setNewMessage('');
      setErrorMessage('');
    } else {
      const errorData = await response.json();
      console.log(errorData);
      setErrorMessage(`Couldn't send message: ${errorData.error}`);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/");
  };

  const handleLoginAttempts = () => {
    navigate('/login-attempts');
  };

  return (
    <div>
      <h1>BetterTwitter</h1>
      <button onClick={handleLogout} style={{ marginBottom: "20px" }}>
        Logout
      </button>
      <button onClick={handleLoginAttempts} stype={{ marginBottom: "20px" }}>
	  See login attempts
      </button>
      <h2>Send a Message</h2>
      <textarea
        value={newMessage}
        onChange={(e) => setNewMessage(e.target.value)}
        placeholder="Write your message here..."
      />
      <br />
      <button onClick={sendMessage}>Send</button>
      {errorMessage && <p style={{ color: 'red' }}>{errorMessage}</p>}
      <h2>Messages</h2>
      <ul className="message-list">
        {messages.map((msg) => (
          <li key={msg.id} className="message">
            <button onClick={() => navigate(`/messages/verify/${msg.id}`)}>?</button>
            <strong>  {msg.username}:</strong>
            <ReactMarkdown>{msg.content}</ReactMarkdown>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default Dashboard;

