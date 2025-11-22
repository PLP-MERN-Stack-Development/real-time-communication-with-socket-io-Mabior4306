import React, { useState, useEffect } from 'react';
import Message from './Message';
import TypingIndicator from './TypingIndicator';
import OnlineUsers from './OnlineUsers';

const Chat = ({ socket, username }) => {
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);
  const [typingUser, setTypingUser] = useState('');
  const [onlineUsers, setOnlineUsers] = useState([]);

  useEffect(() => {
    socket.on('receive_message', (msg) => setMessages(prev => [...prev, msg]));
    socket.on('typing', (user) => {
      setTypingUser(user);
      setTimeout(() => setTypingUser(''), 1000);
    });
    socket.on('online_users', (users) => setOnlineUsers(users));
    return () => socket.off();
  }, [socket]);

  const sendMessage = () => {
    if (!message) return;
    const msg = { username, message, timestamp: new Date().toLocaleTimeString() };
    socket.emit('send_message', msg);
    setMessages(prev => [...prev, msg]);
    setMessage('');
  };

  const handleTyping = () => socket.emit('typing', username);

  return (
    <div>
      <OnlineUsers users={onlineUsers} />
      <div style={{ marginTop: '20px' }}>
        {messages.map((msg, i) => <Message key={i} message={msg} />)}
        <TypingIndicator user={typingUser} />
      </div>
      <div style={{ marginTop: '10px' }}>
        <input value={message} onChange={e => setMessage(e.target.value)} onKeyPress={handleTyping} />
        <button onClick={sendMessage}>Send</button>
      </div>
    </div>
  );
};

export default Chat;
