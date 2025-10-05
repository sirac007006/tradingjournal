import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import pkg from 'pg';
import bcrypt from 'bcrypt';

const { Pool } = pkg;

// ES Module workaround for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL connection pool
const pool = new Pool({
  user: 'marko',
  password: 'O95iBz6rttFi1PJDPZRcXuQIF50rn1Rh',
  host: 'd0j277ffte5s73c6kp70-a.oregon-postgres.render.com',
  port: 5432,
  database: 'mazor_ngl2',
  ssl: {
    rejectUnauthorized: false
  }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Database connection error:', err);
  } else {
    console.log('✅ Database connected successfully at', res.rows[0].now);
  }
});

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'trading-journal-secret-key-2025',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 // 24 hours
    }
  })
);

// Make user available in all views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    return next();
  }
  res.redirect('/login');
};

// ============================================
// ROUTES
// ============================================

// Home route - redirect to login or journal
app.get('/', (req, res) => {
  if (req.session.user) {
    res.redirect('/journal');
  } else {
    res.redirect('/login');
  }
});

// ============================================
// REGISTER ROUTES
// ============================================

// GET - Register page
app.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/journal');
  }
  res.render('register', { title: 'Register', error: null });
});

// POST - Register new user
app.post('/register', async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  try {
    // Validation
    if (!username || !email || !password || !confirmPassword) {
      return res.render('register', {
        title: 'Register',
        error: 'All fields are required'
      });
    }

    if (password !== confirmPassword) {
      return res.render('register', {
        title: 'Register',
        error: 'Passwords do not match'
      });
    }

    if (password.length < 6) {
      return res.render('register', {
        title: 'Register',
        error: 'Password must be at least 6 characters'
      });
    }

    // Check if user already exists
    const userExists = await pool.query(
      'SELECT * FROM tradingusers WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (userExists.rows.length > 0) {
      return res.render('register', {
        title: 'Register',
        error: 'Username or email already exists'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    const result = await pool.query(
      'INSERT INTO tradingusers (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, hashedPassword]
    );

    // Auto-login after registration
    req.session.user = {
      id: result.rows[0].id,
      username: result.rows[0].username,
      email: result.rows[0].email
    };

    res.redirect('/journal');
  } catch (error) {
    console.error('Register error:', error);
    res.render('register', {
      title: 'Register',
      error: 'Registration failed. Please try again.'
    });
  }
});

// ============================================
// LOGIN ROUTES
// ============================================

// GET - Login page
app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/journal');
  }
  res.render('login', { title: 'Login', error: null });
});

// POST - Login authentication
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      return res.render('login', {
        title: 'Login',
        error: 'Username and password are required'
      });
    }

    // Find user
    const result = await pool.query(
      'SELECT * FROM tradingusers WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.render('login', {
        title: 'Login',
        error: 'Invalid username or password'
      });
    }

    const user = result.rows[0];

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.render('login', {
        title: 'Login',
        error: 'Invalid username or password'
      });
    }

    // Set session
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email
    };

    res.redirect('/journal');
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', {
      title: 'Login',
      error: 'Login failed. Please try again.'
    });
  }
});

// ============================================
// LOGOUT ROUTE
// ============================================

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/login');
  });
});

// ============================================
// JOURNAL ROUTE (Protected)
// ============================================

app.get('/journal', isAuthenticated, async (req, res) => {
  try {
    // Get all trades for logged-in user
    const tradesResult = await pool.query(
      'SELECT * FROM trades WHERE user_id = $1 ORDER BY trade_date DESC, id DESC',
      [req.session.user.id]
    );

    const trades = tradesResult.rows;

    // Calculate statistics
    let totalProfit = 0;
    let winningTrades = 0;
    let totalTrades = trades.length;

    trades.forEach(trade => {
      if (trade.profit_loss) {
        totalProfit += parseFloat(trade.profit_loss);
        if (parseFloat(trade.profit_loss) > 0) {
          winningTrades++;
        }
      }
    });

    const winRate = totalTrades > 0 ? ((winningTrades / totalTrades) * 100).toFixed(2) : 0;

    // Prepare chart data (profit by date)
    const chartData = {};
    trades.forEach(trade => {
      const date = trade.trade_date.toISOString().split('T')[0];
      if (!chartData[date]) {
        chartData[date] = 0;
      }
      chartData[date] += parseFloat(trade.profit_loss || 0);
    });

    res.render('journal', {
      title: 'Trading Journal',
      trades,
      stats: {
        totalProfit: totalProfit.toFixed(2),
        winRate,
        totalTrades
      },
      chartData: JSON.stringify(chartData)
    });
  } catch (error) {
    console.error('Journal error:', error);
    res.render('error', {
      title: 'Error',
      message: 'Failed to load journal',
      error
    });
  }
});

// ============================================
// ADD TRADE ROUTES
// ============================================

// GET - Add trade form
app.get('/trades/add', isAuthenticated, (req, res) => {
  res.render('addTrade', { title: 'Add Trade', error: null });
});

// POST - Create new trade
app.post('/trades/add', isAuthenticated, async (req, res) => {
  const { pair, position, entry_price, exit_price, profit_loss, comment, trade_date } = req.body;

  try {
    if (!pair || !position) {
      return res.render('addTrade', {
        title: 'Add Trade',
        error: 'Pair and position are required'
      });
    }

    await pool.query(
      'INSERT INTO trades (user_id, pair, position, entry_price, exit_price, profit_loss, comment, trade_date) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [
        req.session.user.id,
        pair,
        position,
        entry_price || null,
        exit_price || null,
        profit_loss || null,
        comment || null,
        trade_date || new Date()
      ]
    );

    res.redirect('/journal');
  } catch (error) {
    console.error('Add trade error:', error);
    res.render('addTrade', {
      title: 'Add Trade',
      error: 'Failed to add trade. Please try again.'
    });
  }
});

// ============================================
// EDIT TRADE ROUTES
// ============================================

// GET - Edit trade form
app.get('/trades/edit/:id', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM trades WHERE id = $1 AND user_id = $2',
      [req.params.id, req.session.user.id]
    );

    if (result.rows.length === 0) {
      return res.redirect('/journal');
    }

    const trade = result.rows[0];
    // Format date for input field
    trade.trade_date = trade.trade_date.toISOString().split('T')[0];

    res.render('editTrade', {
      title: 'Edit Trade',
      trade,
      error: null
    });
  } catch (error) {
    console.error('Edit trade error:', error);
    res.redirect('/journal');
  }
});

// POST - Update trade
app.post('/trades/edit/:id', isAuthenticated, async (req, res) => {
  const { pair, position, entry_price, exit_price, profit_loss, comment, trade_date } = req.body;

  try {
    if (!pair || !position) {
      const trade = { id: req.params.id, ...req.body };
      return res.render('editTrade', {
        title: 'Edit Trade',
        trade,
        error: 'Pair and position are required'
      });
    }

    const result = await pool.query(
      'UPDATE trades SET pair = $1, position = $2, entry_price = $3, exit_price = $4, profit_loss = $5, comment = $6, trade_date = $7 WHERE id = $8 AND user_id = $9',
      [
        pair,
        position,
        entry_price || null,
        exit_price || null,
        profit_loss || null,
        comment || null,
        trade_date || new Date(),
        req.params.id,
        req.session.user.id
      ]
    );

    if (result.rowCount === 0) {
      return res.redirect('/journal');
    }

    res.redirect('/journal');
  } catch (error) {
    console.error('Update trade error:', error);
    const trade = { id: req.params.id, ...req.body };
    res.render('editTrade', {
      title: 'Edit Trade',
      trade,
      error: 'Failed to update trade. Please try again.'
    });
  }
});

// ============================================
// DELETE TRADE ROUTE
// ============================================

app.post('/trades/delete/:id', isAuthenticated, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM trades WHERE id = $1 AND user_id = $2',
      [req.params.id, req.session.user.id]
    );

    res.redirect('/journal');
  } catch (error) {
    console.error('Delete trade error:', error);
    res.redirect('/journal');
  }
});

// ============================================
// ERROR HANDLERS
// ============================================

// 404 Handler
app.use((req, res) => {
  res.status(404).send('<h1>404 - Page Not Found</h1><a href="/">Go Home</a>');
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('<h1>500 - Server Error</h1><p>Something went wrong!</p>');
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`🚀 Trading Journal server running on http://localhost:${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});