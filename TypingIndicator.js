import React from 'react';

const TypingIndicator = ({ user }) => user ? <p><em>{user} is typing...</em></p> : null;

export default TypingIndicator;
