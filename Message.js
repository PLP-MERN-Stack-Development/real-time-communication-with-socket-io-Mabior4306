import React from 'react';

const Message = ({ message }) => (
  <div style={{ padding: '5px', borderBottom: '1px solid #ccc' }}>
    <strong>{message.username}</strong> [{message.timestamp}]: {message.message}
  </div>
);

export default Message;
