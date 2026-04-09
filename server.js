const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const sanitizeHtml = require('sanitize-html');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
// Rate limiter for auth endpoints to mitigate brute force
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many requests, please try again later.' } });

const { getDb, closeDatabase } = require('./database');

function validateEmail(email) {
  const regex = /^[a-zA-Z]+\.[a-zA-Z]+\d+-[a-zA-Z]+@basischina\.com$/;  
  return regex.test(email);
}

function readJson(filePath) {
  try {
    if (!fs.existsSync(filePath)) return {};
    return JSON.parse(fs.readFileSync(filePath, 'utf8') || '{}');
  } catch (e) {
    return {};
  } 
}

// Helper function to get session from cookie and validate
function getSessionFromCookie(req, res) {
  return new Promise((resolve, reject) => {
    const token = req.cookies.sessionToken;
    if (!token) {
      resolve(null);
      return;
    }
    
    const db = getDatabase();
    db.get('SELECT * FROM sessions WHERE token = ?', [token], (err, session) => {
      if (err) {
        reject(err);
        return;
      }
      
      if (!session) {
        resolve(null);
        return;
      }
      
      // Check expiry
      if (new Date(session.expiresAt) < new Date()) {
        // Delete expired session
        db.run('DELETE FROM sessions WHERE token = ?', [token], (err) => {
          if (err) {
            reject(err);
            return;
          }
          res.clearCookie('sessionToken');
          resolve(null);
        });
      } else {
        resolve(session);
      }
    });
  });
}

// Signup
app.post('/api/signup', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  if (!validateEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  const emailKey = email.toLowerCase();

  const db = getDatabase();
  
  // Check if user already exists
  db.get('SELECT * FROM users WHERE email = ?', [emailKey], async (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    if (user) return res.status(400).json({ error: 'Account already exists' });

    if (password.length < 6) return res.status(400).json({ error: 'Password too short (min 6 chars)' });

    const hash = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();
    
    // Insert user
    db.run('INSERT INTO users (email, passwordHash, createdAt) VALUES (?, ?, ?)', 
      [emailKey, hash, createdAt], function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      // create session with expiry (24 hours)
      const token = uuidv4();
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      
      db.run('INSERT INTO sessions (token, email, createdAt, expiresAt) VALUES (?, ?, ?, ?)', 
        [token, emailKey, createdAt, expiresAt], function(err) {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        // Set HttpOnly cookie (expires in 24 hours)
        res.cookie('sessionToken', token, { httpOnly: true, sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 });
        res.json({ email: emailKey });
      });
    });
  });
});

// Login
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  if (!validateEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  const emailKey = email.toLowerCase();

  const db = getDatabase();
  
  // Get user
  db.get('SELECT * FROM users WHERE email = ?', [emailKey], async (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    if (!user) return res.status(400).json({ error: 'No account for that email' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    // Create session
    const token = uuidv4();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const createdAt = new Date().toISOString();
    
    db.run('INSERT INTO sessions (token, email, createdAt, expiresAt) VALUES (?, ?, ?, ?)', 
      [token, emailKey, createdAt, expiresAt], function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      // Set HttpOnly cookie (expires in 24 hours)
      res.cookie('sessionToken', token, { httpOnly: true, sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 });
      res.json({ email: emailKey });
    });
  });
});

// Check session (reads from cookie)
app.get('/api/session', (req, res) => {
  getSessionFromCookie(req, res)
    .then(session => {
      if (!session) return res.json({ loggedIn: false });
      res.json({ loggedIn: true, email: session.email });
    })
    .catch(err => {
      console.error('Database error:', err);
      res.status(500).json({ error: 'Internal server error' });
    });
});

// Logout
app.post('/api/logout', (req, res) => {
  const token = req.cookies.sessionToken;
  if (token) {
    const db = getDatabase();
    db.run('DELETE FROM sessions WHERE token = ?', [token], (err) => {
      if (err) {
        console.error('Database error:', err);
      }
    });
  }
  res.clearCookie('sessionToken');
  return res.json({ success: true });
});

// Get account info for current session
app.get('/api/account', (req, res) => {
  getSessionFromCookie(req, res)
    .then(session => {
      if (!session) return res.status(401).json({ error: 'Unauthorized' });
      
      const db = getDatabase();
      db.get('SELECT email, name, icon, createdAt FROM users WHERE email = ?', [session.email], (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        res.json({ email: user.email, name: user.name || '', icon: user.icon || '', createdAt: user.createdAt });
      });
    })
    .catch(err => {
      console.error('Database error:', err);
      res.status(500).json({ error: 'Internal server error' });
    });
});

// Update account info (name, icon, email, password)
app.put('/api/account', async (req, res) => {
  getSessionFromCookie(req, res)
    .then(session => {
      if (!session) return res.status(401).json({ error: 'Unauthorized' });
      
      const { name, icon, email: newEmailRaw, currentPassword, newPassword } = req.body || {};
      const newEmail = newEmailRaw ? newEmailRaw.toLowerCase().trim() : undefined;
      
      // Sanitize name and icon
      const sanitizedName = sanitizeHtml(name || '', { allowedTags: [], allowedAttributes: {} });
      const sanitizedIcon = sanitizeHtml(icon || '', { allowedTags: [], allowedAttributes: {} });
      
      const db = getDatabase();
      
      // Get current user data
      db.get('SELECT * FROM users WHERE email = ?', [session.email], async (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        // If changing email or password, require currentPassword
        if ((newEmail && newEmail !== session.email) || newPassword) {
          if (!currentPassword) return res.status(400).json({ error: 'Current password required to change email or password' });
          const match = await bcrypt.compare(currentPassword, user.passwordHash);
          if (!match) return res.status(400).json({ error: 'Current password incorrect' });
        }
        
        // Update user data
        const updates = [];
        const params = [];
        
        if (sanitizedName) {
          updates.push('name = ?');
          params.push(sanitizedName);
        }
        
        if (sanitizedIcon) {
          updates.push('icon = ?');
          params.push(sanitizedIcon);
        }
        
        // Change password
        if (newPassword) {
          if (newPassword.length < 6) return res.status(400).json({ error: 'New password too short (min 6 chars)' });
          const hash = await bcrypt.hash(newPassword, 10);
          updates.push('passwordHash = ?');
          params.push(hash);
        }
        
        // Change email (re-key user entry)
        if (newEmail && newEmail !== session.email) {
          // Check if new email already exists
          db.get('SELECT * FROM users WHERE email = ?', [newEmail], (err, existingUser) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Internal server error' });
            }
            
            if (existingUser) return res.status(400).json({ error: 'Email already in use' });
            
            // Update user email
            params.push(newEmail);
            updates.push('email = ?');
            
            const updateQuery = `UPDATE users SET ${updates.join(', ')} WHERE email = ?`;
            db.run(updateQuery, [...params, session.email], function(err) {
              if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Internal server error' });
              }
              
              // Update all sessions referencing old email
              db.run('UPDATE sessions SET email = ? WHERE email = ?', [newEmail, session.email], (err) => {
                if (err) {
                  console.error('Database error:', err);
                  return res.status(500).json({ error: 'Internal server error' });
                }
                
                res.json({ email: newEmail, name: sanitizedName || user.name || '', icon: sanitizedIcon || user.icon || '' });
              });
            });
          });
        } else {
          // Regular update
          if (updates.length === 0) {
            return res.json({ email: session.email, name: user.name || '', icon: user.icon || '' });
          }
          
          const updateQuery = `UPDATE users SET ${updates.join(', ')} WHERE email = ?`;
          db.run(updateQuery, [...params, session.email], function(err) {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Internal server error' });
            }
            
            res.json({ email: session.email, name: sanitizedName || user.name || '', icon: sanitizedIcon || user.icon || '' });
          });
        }
      });
    })
    .catch(err => {
      console.error('Database error:', err);
      res.status(500).json({ error: 'Internal server error' });
    });
});

// Get posts
app.get('/api/posts', (req, res) => {
  const db = getDatabase();
  db.all('SELECT * FROM posts ORDER BY createdAt DESC', [], (err, posts) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json({ posts });
  });
});

// Create post (requires session token)
app.post('/api/posts', (req, res) => {
  const session = getSessionFromCookie(req, res);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });

  const { title, content, badge, category } = req.body || {};
  if (!title || !content) return res.status(400).json({ error: 'Missing title or content' });
  // length validations
  if (title.length > 200) return res.status(400).json({ error: 'Title too long (max 200 chars)' });
  if (content.length > 5000) return res.status(400).json({ error: 'Content too long (max 5000 chars)' });
  if (category && category.length > 100) return res.status(400).json({ error: 'Category too long (max 100 chars)' });

  // Sanitize inputs to prevent XSS
  const sanitizedTitle = sanitizeHtml(title, { allowedTags: [], allowedAttributes: {} });
  const sanitizedContent = sanitizeHtml(content, {
    allowedTags: ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'h3', 'pre', 'code'],
    allowedAttributes: {}
  });
  const sanitizedCategory = sanitizeHtml(category || '', { allowedTags: [], allowedAttributes: {} });
  const sanitizedBadge = sanitizeHtml(badge || 'Discussion', { allowedTags: [], allowedAttributes: {} });

  if (!sanitizedTitle.trim() || !sanitizedContent.trim()) {
    return res.status(400).json({ error: 'Title and content cannot be empty' });
  }

  const users = readJson(USERS_FILE);
  const user = users[session.email];
  const displayName = user ? (user.name || session.email.split('@')[0]) : session.email.split('@')[0];
  const avatar = user ? (user.icon || 'default') : 'default';

  const posts = readJson(POSTS_FILE) || {};
  const id = uuidv4();
  posts[id] = {
    title: sanitizedTitle,
    content: sanitizedContent,
    badge: sanitizedBadge,
    badgeClass: sanitizedBadge.toLowerCase() === 'question' ? 'badge-question' : (sanitizedBadge.toLowerCase() === 'tips' ? 'badge-tips' : (sanitizedBadge.toLowerCase() === 'resource' ? 'badge-resource' : 'badge-discussion')),
    author: session.email,
    authorName: displayName,
    authorAvatar: avatar,
    authorEmail: session.email,
    category: sanitizedCategory,
    date: new Date().toISOString(),
    replies: '0 replies',
    likes: 0,
    dislikes: 0,
    userVotes: {}, // email -> 'like' or 'dislike'
    comments: [],
    createdAt: new Date().toISOString()
  };
  writeJson(POSTS_FILE, posts);
  res.json({ id, post: posts[id] });
});

// Edit a post (only author)
app.put('/api/posts/:id', (req, res) => {
  getSessionFromCookie(req, res)
    .then(session => {
      if (!session) return res.status(401).json({ error: 'Unauthorized' });
      
      const id = req.params.id;
      const { title, content, badge, category } = req.body || {};
      
      const db = getDatabase();
      
      // Get post
      db.get('SELECT * FROM posts WHERE id = ?', [id], (err, post) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (!post) return res.status(404).json({ error: 'Post not found' });
        if (post.author !== session.email) return res.status(403).json({ error: 'Forbidden' });
        
        // Validate inputs
        if (title && title.length > 200) return res.status(400).json({ error: 'Title too long (max 200 chars)' });
        if (content && content.length > 5000) return res.status(400).json({ error: 'Content too long (max 5000 chars)' });
        if (category && category.length > 100) return res.status(400).json({ error: 'Category too long (max 100 chars)' });
        
        // Sanitize inputs
        const updates = [];
        const params = [];
        
        if (title) {
          updates.push('title = ?');
          params.push(sanitizeHtml(title, { allowedTags: [], allowedAttributes: {} }));
        }
        
        if (content) {
          updates.push('content = ?');
          params.push(sanitizeHtml(content, { allowedTags: ['p','br','strong','em','u','ol','ul','li','h3','pre','code'], allowedAttributes: {} }));
        }
        
        if (badge) {
          updates.push('badge = ?');
          params.push(sanitizeHtml(badge, { allowedTags: [], allowedAttributes: {} }));
        }
        
        if (category) {
          updates.push('category = ?');
          params.push(sanitizeHtml(category, { allowedTags: [], allowedAttributes: {} }));
        }
        
        if (updates.length > 0) {
          updates.push('updatedAt = ?');
          params.push(new Date().toISOString());
        }
        
        if (updates.length === 0) {
          return res.json({ success: true, post });
        }
        
        const updateQuery = `UPDATE posts SET ${updates.join(', ')} WHERE id = ?`;
        db.run(updateQuery, [...params, id], function(err) {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Internal server error' });
          }
          
          // Get updated post
          db.get('SELECT * FROM posts WHERE id = ?', [id], (err, updatedPost) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Internal server error' });
            }
            
            res.json({ success: true, post: updatedPost });
          });
        });
      });
    })
    .catch(err => {
      console.error('Database error:', err);
      res.status(500).json({ error: 'Internal server error' });
    });
});

// Delete a post (only author)
app.delete('/api/posts/:id', (req, res) => {
  getSessionFromCookie(req, res)
    .then(session => {
      if (!session) return res.status(401).json({ error: 'Unauthorized' });
      
      const id = req.params.id;
      
      const db = getDatabase();
      
      // Get post
      db.get('SELECT * FROM posts WHERE id = ?', [id], (err, post) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (!post) return res.status(404).json({ error: 'Post not found' });
        if (post.author !== session.email) return res.status(403).json({ error: 'Forbidden' });
        
        // Delete post
        db.run('DELETE FROM posts WHERE id = ?', [id], function(err) {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Internal server error' });
          }
          
          res.json({ success: true });
        });
      });
    })
    .catch(err => {
      console.error('Database error:', err);
      res.status(500).json({ error: 'Internal server error' });
    });
});

// Vote on a post
app.post('/api/posts/:id/vote', (req, res) => {
  const session = getSessionFromCookie(req, res);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  const id = req.params.id;
  const { vote } = req.body || {}; // 'like' or 'dislike'
  if (!['like', 'dislike'].includes(vote)) return res.status(400).json({ error: 'Invalid vote' });

  const posts = readJson(POSTS_FILE) || {};
  const post = posts[id];
  if (!post) return res.status(404).json({ error: 'Post not found' });

  const previousVote = post.userVotes[session.email];
  if (previousVote) {
    if (previousVote === 'like') post.likes--;
    else post.dislikes--;
  }

  post.userVotes[session.email] = vote;
  if (vote === 'like') post.likes++;
  else post.dislikes++;

  writeJson(POSTS_FILE, posts);
  res.json({ likes: post.likes, dislikes: post.dislikes, userVote: vote });
});

// Add comment to a post
app.post('/api/posts/:id/comments', (req, res) => {
  const session = getSessionFromCookie(req, res);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  const id = req.params.id;
  const { content } = req.body || {};
  if (!content || !content.trim()) return res.status(400).json({ error: 'Comment content required' });
  if (content.length > 1000) return res.status(400).json({ error: 'Comment too long (max 1000 chars)' });

  const users = readJson(USERS_FILE);
  const user = users[session.email];
  const displayName = user ? (user.name || session.email.split('@')[0]) : session.email.split('@')[0];
  const avatar = user ? (user.icon || 'default') : 'default';

  const posts = readJson(POSTS_FILE) || {};
  const post = posts[id];
  if (!post) return res.status(404).json({ error: 'Post not found' });

  const commentId = uuidv4();
  const comment = {
    id: commentId,
    content: sanitizeHtml(content.trim(), { allowedTags: ['p','br','strong','em','u'], allowedAttributes: {} }),
    author: session.email,
    authorName: displayName,
    authorAvatar: avatar,
    authorEmail: session.email,
    likes: 0,
    dislikes: 0,
    userVotes: {},
    createdAt: new Date().toISOString()
  };

  post.comments = post.comments || [];
  post.comments.push(comment);
  post.replies = `${post.comments.length} replies`;

  writeJson(POSTS_FILE, posts);
  res.json({ comment });
});

// Vote on a comment
app.post('/api/posts/:postId/comments/:commentId/vote', (req, res) => {
  const session = getSessionFromCookie(req, res);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  const postId = req.params.postId;
  const commentId = req.params.commentId;
  const { vote } = req.body || {};
  if (!['like', 'dislike'].includes(vote)) return res.status(400).json({ error: 'Invalid vote' });

  const posts = readJson(POSTS_FILE) || {};
  const post = posts[postId];
  if (!post) return res.status(404).json({ error: 'Post not found' });

  const comment = post.comments.find(c => c.id === commentId);
  if (!comment) return res.status(404).json({ error: 'Comment not found' });

  const previousVote = comment.userVotes[session.email];
  if (previousVote) {
    if (previousVote === 'like') comment.likes--;
    else comment.dislikes--;
  }

  comment.userVotes[session.email] = vote;
  if (vote === 'like') comment.likes++;
  else comment.dislikes++;

  writeJson(POSTS_FILE, posts);
  res.json({ likes: comment.likes, dislikes: comment.dislikes, userVote: vote });
});

// Top contributors
app.get('/api/contributors', (req, res) => {
  const db = getDatabase();
  db.all('SELECT author, COUNT(*) as count FROM posts GROUP BY author ORDER BY count DESC LIMIT 10', [], (err, contributors) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json({ contributors });
  });
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('Received SIGINT. Graceful shutdown...');
  closeDatabase();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM. Graceful shutdown...');
  closeDatabase();
  process.exit(0);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on port ${PORT}`);
});