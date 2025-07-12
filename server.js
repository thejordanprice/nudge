const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');

const server = http.createServer((req, res) => {
  let filePath = '.' + decodeURIComponent(req.url);
  if (filePath === './') filePath = './client.html';
  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
  };
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
    } else {
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' });
      res.end(content, 'utf-8');
    }
  });
});

const wss = new WebSocket.Server({ server });

// In-memory user and connection registry
// normalizedUsername (lowercase) -> { ws, id, preKeyCard, preKeySecret, displayName, lastHeartbeat }
const users = new Map();

// Heartbeat tracking
const heartbeatTimeouts = new Map(); // username -> timeout
const HEARTBEAT_INTERVAL = 5000; // 5 seconds
const HEARTBEAT_TIMEOUT = 10000; // 10 seconds (2x heartbeat interval)

// Broadcast the full user list to all clients
function broadcastUserList() {
  const userList = Array.from(users.values()).map(info => ({ username: info.displayName, id: info.id }));
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'user_list', users: userList }));
    }
  });
}

// Helper: broadcast to all except sender
function broadcastExcept(senderWs, data) {
  wss.clients.forEach(client => {
    if (client !== senderWs && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

// Heartbeat system
function startHeartbeatTimeout(username) {
  // Clear existing timeout
  if (heartbeatTimeouts.has(username)) {
    clearTimeout(heartbeatTimeouts.get(username));
  }
  
  // Set new timeout
  const timeout = setTimeout(() => {
    handleUserDisconnect(username);
  }, HEARTBEAT_TIMEOUT);
  
  heartbeatTimeouts.set(username, timeout);
}

function handleUserDisconnect(username) {
  if (DEBUG) console.log('[DEBUG] User disconnected due to heartbeat timeout:', username);
  
  // Clear timeout
  if (heartbeatTimeouts.has(username)) {
    clearTimeout(heartbeatTimeouts.get(username));
    heartbeatTimeouts.delete(username);
  }
  
  // Remove user and broadcast
  if (users.has(username)) {
    const displayName = users.get(username).displayName;
    users.delete(username);
    broadcastUserList();
    
    // Broadcast user_left event
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: 'user_left', username: displayName }));
      }
    });
  }
}

// Debug flag
const DEBUG = process.argv.includes('--debug');

wss.on('connection', (ws) => {
  if (DEBUG) console.log('[DEBUG] WebSocket connection established');
  let username = null; // normalized (lowercase)
  let displayName = null; // original casing

  ws.on('message', (message) => {
    if (DEBUG) {
      let msgStr = message;
      if (Buffer.isBuffer(message)) {
        msgStr = message.toString('utf8');
      }
      console.log('[DEBUG] Received message:', msgStr);
    }
    let data;
    try {
      data = JSON.parse(message);
    } catch (e) {
      ws.send(JSON.stringify({ type: 'error', error: 'Invalid JSON' }));
      return;
    }

    switch (data.type) {
      case 'register': {
        // { type: 'register', username, id }
        if (!data.username || !data.id) {
          ws.send(JSON.stringify({ type: 'error', error: 'Missing username or id' }));
          return;
        }
        const normalized = data.username.trim().toLowerCase();
        if (users.has(normalized)) {
          ws.send(JSON.stringify({ type: 'error', error: 'Username already taken' }));
          return;
        }
        username = normalized;
        displayName = data.username;
        users.set(username, { ws, id: data.id, displayName, lastHeartbeat: Date.now() });
        ws.send(JSON.stringify({ type: 'registered', username: displayName }));
        broadcastUserList();
        
        // Start heartbeat timeout for new user
        startHeartbeatTimeout(username);
        break;
      }
      case 'list_users': {
        // { type: 'list_users' }
        const userList = Array.from(users.values()).map(info => ({ username: info.displayName, id: info.id }));
        ws.send(JSON.stringify({ type: 'user_list', users: userList }));
        break;
      }
      case 'prekey': {
        // { type: 'prekey', card, secret }
        if (!username) {
          ws.send(JSON.stringify({ type: 'error', error: 'Not registered' }));
          return;
        }
        users.get(username).preKeyCard = data.card;
        users.get(username).preKeySecret = data.secret;
        ws.send(JSON.stringify({ type: 'prekey_saved' }));
        break;
      }
      case 'get_prekey': {
        // { type: 'get_prekey', username }
        const normalized = data.username.trim().toLowerCase();
        const target = users.get(normalized);
        if (!target || !target.preKeyCard) {
          ws.send(JSON.stringify({ type: 'error', error: 'No pre-key for user' }));
          return;
        }
        ws.send(JSON.stringify({ type: 'prekey', username: target.displayName, card: target.preKeyCard }));
        break;
      }
      case 'relay': {
        // { type: 'relay', to, from, payload }
        const normalizedTo = data.to.trim().toLowerCase();
        const target = users.get(normalizedTo);
        if (!target) {
          ws.send(JSON.stringify({ type: 'error', error: 'User not found' }));
          return;
        }
        target.ws.send(JSON.stringify({ type: 'message', from: data.from, payload: data.payload }));
        break;
      }
      case 'signal': {
        // { type: 'signal', to, from, data } (for session establishment, e.g. init data)
        const normalizedTo = data.to.trim().toLowerCase();
        const target = users.get(normalizedTo);
        if (!target) {
          ws.send(JSON.stringify({ type: 'error', error: 'User not found' }));
          return;
        }
        target.ws.send(JSON.stringify({ type: 'signal', from: data.from, data: data.data }));
        break;
      }
      case 'heartbeat': {
        // { type: 'heartbeat', username }
        if (!username) {
          ws.send(JSON.stringify({ type: 'error', error: 'Not registered' }));
          return;
        }
        
        // Update last heartbeat time
        if (users.has(username)) {
          users.get(username).lastHeartbeat = Date.now();
        }
        
        // Restart heartbeat timeout
        startHeartbeatTimeout(username);
        
        // Send heartbeat response
        ws.send(JSON.stringify({ type: 'heartbeat_response' }));
        break;
      }
      default:
        ws.send(JSON.stringify({ type: 'error', error: 'Unknown action' }));
    }
  });

  ws.on('close', () => {
    if (DEBUG) console.log('[DEBUG] WebSocket connection closed for', username || '(unknown)');
    if (username && users.has(username)) {
      const displayName = users.get(username).displayName;
      
      // Clean up heartbeat timeout
      if (heartbeatTimeouts.has(username)) {
        clearTimeout(heartbeatTimeouts.get(username));
        heartbeatTimeouts.delete(username);
      }
      
      users.delete(username);
      broadcastUserList();
      // Broadcast user_left event
      wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: 'user_left', username: displayName }));
        }
      });
    }
  });

  ws.on('error', (err) => {
    if (DEBUG) console.log('[DEBUG] WebSocket error:', err);
  });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`WebSocket relay server and static file server running on port ${PORT}`);
  console.log(`Open http://localhost:${PORT}/ in your browser.`);
}); 