const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Database file path
const DB_PATH = path.join(__dirname, 'database.sqlite');

// Create database connection
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database');
  }
});

// Initialize database tables
function initializeDatabase(callback) {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      passwordHash TEXT NOT NULL,
      name TEXT,
      icon TEXT,
      createdAt TEXT NOT NULL
    )
  `, (err) => {
    if (err) return callback(err);
    
    // Sessions table
    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        createdAt TEXT NOT NULL,
        expiresAt TEXT NOT NULL,
        FOREIGN KEY (email) REFERENCES users (email) ON DELETE CASCADE
      )
    `, (err) => {
      if (err) return callback(err);
      
      // Posts table
      db.run(`
        CREATE TABLE IF NOT EXISTS posts (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          badge TEXT NOT NULL,
          badgeClass TEXT NOT NULL,
          author TEXT NOT NULL,
          category TEXT,
          date TEXT NOT NULL,
          replies TEXT NOT NULL,
          createdAt TEXT NOT NULL,
          updatedAt TEXT,
          FOREIGN KEY (author) REFERENCES users (email) ON DELETE CASCADE
        )
      `, (err) => {
        if (err) return callback(err);
        
        // Create indexes for better performance
        db.run(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`, (err) => {
          if (err) return callback(err);
          
          db.run(`CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email)`, (err) => {
            if (err) return callback(err);
            
            db.run(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expiresAt)`, (err) => {
              if (err) return callback(err);
              
              db.run(`CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author)`, (err) => {
                if (err) return callback(err);
                
                db.run(`CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(createdAt)`, (err) => {
                  if (err) return callback(err);
                  
                  console.log('Database tables initialized');
                  callback(null);
                });
              });
            });
          });
        });
      });
    });
  });
}

// Get database connection
function getDb() {
  return db;
}

// Close database connection
function closeDatabase() {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed');
    }
  });
}

// Export functions
module.exports = {
  initializeDatabase,
  getDb,
  closeDatabase,
  DB_PATH
};