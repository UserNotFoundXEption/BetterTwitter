import React, { useState } from "react";

function RequestPasswordReset() {
  const [email, setEmail] = useState("");
  const [resetLink, setResetLink] = useState("");

  const handleRequestReset = async () => {
    try {
      const response = await fetch("http://localhost:5000/request-password-reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      if (data.reset_link) {
        setResetLink("http://localhost:3000" + data.reset_link);
      } else {
        alert(data.error);
      }
    } catch (error) {
      console.error("Error:", error);
    }
  };

  return (
    <div>
      <h1>Reset password</h1>
      <input
        type="email"
        placeholder="Your email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <button onClick={handleRequestReset}>Request password reset</button>
      {resetLink && (
        <div>
          <p>Password reset link that would normally be sent through email:</p>
          <a href={resetLink}>{resetLink}</a>
        </div>
      )}
    </div>
  );
}

export default RequestPasswordReset;

