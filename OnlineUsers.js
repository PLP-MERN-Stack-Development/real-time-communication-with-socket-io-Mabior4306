import React from 'react';

const OnlineUsers = ({ users }) => (
  <div>
    <h4>Online Users:</h4>
    <ul>{users.map((u, i) => <li key={i}>{u}</li>)}</ul>
  </div>
);

export default OnlineUsers;
