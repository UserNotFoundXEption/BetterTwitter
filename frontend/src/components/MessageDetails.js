import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

const MessageDetails = () => {
  const { messageId } = useParams();
  const [messageDetails, setMessageDetails] = useState(null);

  useEffect(() => {
    fetch(`https://127.0.0.1/messages/verify/${messageId}`)
      .then((response) => response.json())
      .then((data) => setMessageDetails(data))
      .catch((error) => console.error("Error fetching message details:", error));
  }, [messageId]);

  if (!messageDetails) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <h1>Message Details</h1>
      <p>
        <strong>Content:</strong> {messageDetails.content}
      </p>
      <p>
        <strong>Signature:</strong> {messageDetails.signature}
      </p>
      <p>
        <strong>Public Key:</strong> <pre>{messageDetails.public_key}</pre>
      </p>
      <p>
        <strong>Verification Status:</strong> {messageDetails.verification_status}
      </p>
    </div>
  );
};

export default MessageDetails;

