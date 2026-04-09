const fs = require('fs');
const path = require('path');
const { initializeDatabase, getDb, closeDatabase } = require('./database');

// File paths
const USERS_FILE = path.join(__dirname, 'users.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const POSTS_FILE = path.join(__dirname, 'posts.json');

// Read JSON files
function readJson(filePath) {
  try {
    if (!fs.existsSync(filePath)) return {};
    return JSON.parse(fs.readFileSync(filePath, 'utf8') || '{}');
  } catch (e) {
    console.error(`Error reading ${filePath}:`, e);
    return {};
  }
}

// Migrate users data
function migrateUsers() {
  const users = readJson(USERS_FILE);
  const db = getDb();
  
  return new Promise((resolve, reject) => {
    const stmt = db.prepare('INSERT OR REPLACE INTO users (email, passwordHash, name, icon, createdAt) VALUES (?, ?, ?, ?, ?)');
    
    let count = 0;
    for (const [email, user] of Object.entries(users)) {
      stmt.run(
        email,
        user.passwordHash,
        user.name || null,
        user.icon || null,
        user.createdAt || new Date().toISOString()
      );
      count++;
    }
    
    stmt.finalize((err) => {
      if (err) {
        console.error('Error migrating users:', err);
        reject(err);
      } else {
        console.log(`Migrated ${count} users`);
        resolve();
      }
    });
  });
}

// Migrate sessions data
function migrateSessions() {
  const sessions = readJson(SESSIONS_FILE);
  const db = getDb();
  
  return new Promise((resolve, reject) => {
    const stmt = db.prepare('INSERT OR REPLACE INTO sessions (token, email, createdAt, expiresAt) VALUES (?, ?, ?, ?)');
    
    let count = 0;
    for (const [token, session] of Object.entries(sessions)) {
      stmt.run(
        token,
        session.email,
        session.createdAt,
        session.expiresAt
      );
      count++;
    }
    
    stmt.finalize((err) => {
      if (err) {
        console.error('Error migrating sessions:', err);
        reject(err);
      } else {
        console.log(`Migrated ${count} sessions`);
        resolve();
      }
    });
  });
}

// Migrate posts data
function migratePosts() {
  const posts = readJson(POSTS_FILE);
  const db = getDb();
  
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(`INSERT OR REPLACE INTO posts 
      (id, title, content, badge, badgeClass, author, category, date, replies, createdAt, updatedAt) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    
    let count = 0;
    for (const [id, post] of Object.entries(posts)) {
      stmt.run(
        id,
        post.title,
        post.content,
        post.badge,
        post.badgeClass,
        post.author,
        post.category || null,
        post.date,
        post.replies,
        post.createdAt,
        post.updatedAt || null
      );
      count++;
    }
    
    stmt.finalize((err) => {
      if (err) {
        console.error('Error migrating posts:', err);
        reject(err);
      } else {
        console.log(`Migrated ${count} posts`);
        resolve();
      }
    });
  });
}

// Main migration function
function migrateData() {
  console.log('Starting database migration...');
  
  // Initialize database
  initializeDatabase((err) => {
    if (err) {
      console.error('Error initializing database:', err);
      return;
    }
    
    // Migrate data
    migrateUsers()
      .then(() => migrateSessions())
      .then(() => migratePosts())
      .then(() => {
        console.log('Migration completed successfully!');
        
        // Verify migration
        const db = getDb();
        db.all('SELECT COUNT(*) as count FROM users', [], (err, rows) => {
          if (err) {
            console.error('Error verifying users migration:', err);
          } else {
            console.log(`Users table contains ${rows[0].count} records`);
          }
        });
        
        db.all('SELECT COUNT(*) as count FROM sessions', [], (err, rows) => {
          if (err) {
            console.error('Error verifying sessions migration:', err);
          } else {
            console.log(`Sessions table contains ${rows[0].count} records`);
          }
        });
        
        db.all('SELECT COUNT(*) as count FROM posts', [], (err, rows) => {
          if (err) {
            console.error('Error verifying posts migration:', err);
          } else {
            console.log(`Posts table contains ${rows[0].count} records`);
          }
        });
        
        closeDatabase();
      })
      .catch((error) => {
        console.error('Migration failed:', error);
        closeDatabase();
      });
  });
}

// Run migration if this file is executed directly
if (require.main === module) {
  migrateData();
}

module.exports = { migrateUsers, migrateSessions, migratePosts };