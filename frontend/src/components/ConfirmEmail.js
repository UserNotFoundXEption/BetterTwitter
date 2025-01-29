import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import "../styles/styles.css";

const ConfirmEmail = () => {
  const { token } = useParams();
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
    
  useEffect(() => {
    const confirmEmail = async () => {
      try {
        setError("");
        const response = await fetch(`https://127.0.0.1/confirm-email/${token}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        });

        const data = await response.json();
        if (response.ok) {
          setMessage(data.message);
        } else {
          setError(data.error || "Failed to confirm email.");
        }
      } catch (error) {
        setError("Error: " + error.message);
      }
    };

    confirmEmail();
  }, [token]);

  return (
    <div>
      <h1>Verify email</h1>
      {message && <p style={{ color: "green" }}>{message}</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}
    </div>
  );
};

export default ConfirmEmail;

