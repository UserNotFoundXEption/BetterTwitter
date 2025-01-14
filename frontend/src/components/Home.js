import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import "../styles/styles.css";

const Home = () => {
  const [redirectToDashboard, setRedirectToDashboard] = useState(false);
  const [messages, setMessages] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      fetch("http://127.0.0.1:5000/validate_token", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })
        .then((response) => {
          if (response.ok) {
            setRedirectToDashboard(true);
          }
        })
        .catch(() => {});
    }

    if (redirectToDashboard) {
      return <Navigate to="/dashboard" />;
    }

    fetch("http://127.0.0.1:5000/messages")
      .then((response) => response.json())
      .then((data) => setMessages(data))
      .catch((error) => console.error("Error fetching messages:", error));
  }, []);

  return (
    <div>
      <h1>BetterTwitter</h1>
      <nav>
        <Link to="/login">Login</Link> | <Link to="/register">Register</Link>
      </nav>
      <p>This is the homepage. Log in to access your dashboard.</p>

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

export default Home;

