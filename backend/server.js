const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { pool, initDB } = require('./config/db');
const { auth, authorize } = require('./middleware/auth');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Initialize database
initDB();

// Validation middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Validation error', details: errors.array() });
  }
  next();
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

// Auth Routes with validation
app.post('/api/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
  body('role').isIn(['manager', 'intern']).withMessage('Role must be either manager or intern')
], handleValidationErrors, async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    
    // Check if user already exists
    const [existingUsers] = await pool.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const [result] = await pool.execute(
      'INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, name, role]
    );
    
    res.status(201).json({ 
      message: 'User created successfully', 
      userId: result.insertId 
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required')
], handleValidationErrors, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    
    if (!users.length) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Update last login
    await pool.execute(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
      [user.id]
    );
    
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Task Routes with enhanced validation - FIXED VERSION
app.get('/api/tasks', auth, async (req, res) => {
  try {
        const { status, priority, page = 1, limit = 10 } = req.query;

        const safePage = parseInt(page, 10) || 1;
        const safeLimit = parseInt(limit, 10) || 10;
        const offset = (safePage - 1) * safeLimit;

        let baseQuery = `
      SELECT t.*, u.name AS assigned_to_name, c.name AS created_by_name
      FROM tasks t
      LEFT JOIN users u ON t.assigned_to = u.id
      LEFT JOIN users c ON t.created_by = c.id
    `;

        let countQuery = `
      SELECT COUNT(*) AS total
      FROM tasks t
    `;

        const conditions = [];
        const params = [];

        if (req.user.role === 'intern') {
            conditions.push('t.assigned_to = ?');
            params.push(req.user.id);
        }

        if (status && status.trim()) {
            conditions.push('t.status = ?');
            params.push(status.trim());
        }

        if (priority && priority.trim()) {
            conditions.push('t.priority = ?');
            params.push(priority.trim());
        }

        if (conditions.length > 0) {
            const whereClause = ' WHERE ' + conditions.join(' AND ');
            baseQuery += whereClause;
            countQuery += whereClause;
        }

        // 👇 Inline LIMIT and OFFSET to avoid MySQL parameter issues
        baseQuery += ` ORDER BY t.created_at DESC LIMIT ${safeLimit} OFFSET ${offset}`;

        console.log('Executing SQL:', baseQuery);
        console.log('With Params:', params);

        const [tasks] = await pool.execute(baseQuery, params);
        const [countResult] = await pool.execute(countQuery, params);

        res.json({
            tasks,
            pagination: {
                page: safePage,
                limit: safeLimit,
                total: countResult[0].total,
                pages: Math.ceil(countResult[0].total / safeLimit),
            },
        });
    } catch (error) {
        console.error('Get tasks error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.post('/api/tasks', auth, authorize(['manager']), [
  body('title').trim().isLength({ min: 3 }).withMessage('Title must be at least 3 characters'),
  body('description').optional().trim(),
  body('assigned_to').isInt().withMessage('Assigned user must be a valid user ID'),
  body('priority').isIn(['low', 'medium', 'high']).withMessage('Priority must be low, medium, or high'),
  body('due_date').optional().isISO8601().withMessage('Due date must be a valid date')
], handleValidationErrors, async (req, res) => {
  try {
    const { title, description, assigned_to, priority, due_date } = req.body;
    
    // Verify assigned user exists and is an intern
    const [assignedUser] = await pool.execute(
      'SELECT id, role FROM users WHERE id = ?',
      [assigned_to]
    );
    
    if (!assignedUser.length || assignedUser[0].role !== 'intern') {
      return res.status(400).json({ error: 'Can only assign tasks to interns' });
    }
    
    const [result] = await pool.execute(
      'INSERT INTO tasks (title, description, assigned_to, created_by, priority, due_date) VALUES (?, ?, ?, ?, ?, ?)',
      [title, description, assigned_to, req.user.id, priority, due_date]
    );
    
    res.status(201).json({ 
      message: 'Task created successfully', 
      taskId: result.insertId 
    });
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/tasks/:id/status', auth, [
  body('status').isIn(['pending', 'in_progress', 'completed']).withMessage('Invalid status')
], handleValidationErrors, async (req, res) => {
  try {
    const { status } = req.body;
    const taskId = req.params.id;
    
    // Check if task exists and user has permission
    const [tasks] = await pool.execute(
      'SELECT * FROM tasks WHERE id = ?',
      [taskId]
    );
    
    if (!tasks.length) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    const task = tasks[0];
    
    // Interns can only update their own tasks
    if (req.user.role === 'intern' && task.assigned_to !== req.user.id) {
      return res.status(403).json({ error: 'Can only update your own tasks' });
    }
    
    await pool.execute(
      'UPDATE tasks SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [status, taskId]
    );
    
    res.json({ message: 'Task status updated successfully' });
  } catch (error) {
    console.error('Update task status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Leave Routes with enhanced validation
app.get('/api/leave-requests', auth, async (req, res) => {
  try {
    const { status, page = 1, limit = 10 } = req.query;
    
    const safePage = parseInt(page, 10) || 1;
    const safeLimit = parseInt(limit, 10) || 10;
    const offset = (safePage - 1) * safeLimit;

    
    let query = `
      SELECT lr.*, u.name as user_name, u.email as user_email
      FROM leave_requests lr
      JOIN users u ON lr.user_id = u.id
    `;
    
    const conditions = [];
    const params = [];
    
    if (req.user.role === 'intern') {
      conditions.push('lr.user_id = ?');
      params.push(req.user.id);
    }
    
    if (status) {
      conditions.push('lr.status = ?');
      params.push(status);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ` ORDER BY lr.created_at DESC LIMIT ${safeLimit} OFFSET ${offset} `;
    
    const [requests] = await pool.execute(query, params);
    res.json(requests);
  } catch (error) {
    console.error('Get leave requests error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/api/leave-requests', auth, authorize(['intern']), [
  body('start_date').isISO8601().withMessage('Start date must be a valid date'),
  body('end_date').isISO8601().withMessage('End date must be a valid date'),
  body('reason').trim().isLength({ min: 10 }).withMessage('Reason must be at least 10 characters')
], handleValidationErrors, async (req, res) => {
  try {
    const { start_date, end_date, reason } = req.body;
    
    // Validate date logic
    if (new Date(start_date) >= new Date(end_date)) {
      return res.status(400).json({ error: 'End date must be after start date' });
    }
    
    if (new Date(start_date) < new Date()) {
      return res.status(400).json({ error: 'Start date cannot be in the past' });
    }
    
    // Check for overlapping leave requests
    const [overlapping] = await pool.execute(
      `SELECT id FROM leave_requests 
       WHERE user_id = ? AND status = 'approved' 
       AND ((start_date <= ? AND end_date >= ?) OR (start_date <= ? AND end_date >= ?))`,
      [req.user.id, start_date, start_date, end_date, end_date]
    );
    
    if (overlapping.length > 0) {
      return res.status(400).json({ error: 'You already have approved leave for these dates' });
    }
    
    const [result] = await pool.execute(
      'INSERT INTO leave_requests (user_id, start_date, end_date, reason) VALUES (?, ?, ?, ?)',
      [req.user.id, start_date, end_date, reason]
    );
    
    res.status(201).json({ 
      message: 'Leave request submitted successfully',
      requestId: result.insertId
    });
  } catch (error) {
    console.error('Create leave request error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/leave-requests/:id', auth, authorize(['manager']), [
  body('status').isIn(['approved', 'rejected']).withMessage('Status must be approved or rejected')
], handleValidationErrors, async (req, res) => {
  try {
    const { status } = req.body;
    const requestId = req.params.id;
    
    // Check if request exists
    const [requests] = await pool.execute(
      'SELECT * FROM leave_requests WHERE id = ?',
      [requestId]
    );
    
    if (!requests.length) {
      return res.status(404).json({ error: 'Leave request not found' });
    }
    
    if (requests[0].status !== 'pending') {
      return res.status(400).json({ error: 'Can only update pending requests' });
    }
    
    await pool.execute(
      'UPDATE leave_requests SET status = ? WHERE id = ?',
      [status, requestId]
    );
    
    res.json({ message: `Leave request ${status} successfully` });
  } catch (error) {
    console.error('Update leave request error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Challenge Routes with enhanced validation
app.get('/api/challenges', auth, async (req, res) => {
  try {
    const { status, page = 1, limit = 10 } = req.query;
    
    const safePage = parseInt(page, 10) || 1;
    const safeLimit = parseInt(limit, 10) || 10;
    const offset = (safePage - 1) * safeLimit;

    
    let query = `
      SELECT c.*, u.name as user_name, t.title as task_title
      FROM challenges c
      JOIN users u ON c.user_id = u.id
      LEFT JOIN tasks t ON c.task_id = t.id
    `;
    
    const conditions = [];
    const params = [];
    
    if (req.user.role === 'intern') {
      conditions.push('c.user_id = ?');
      params.push(req.user.id);
    }
    
    if (status) {
      conditions.push('c.status = ?');
      params.push(status);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ` ORDER BY c.created_at DESC LIMIT ${safeLimit} OFFSET ${offset}`;
    
    const [challenges] = await pool.execute(query, params);
    res.json(challenges);
  } catch (error) {
    console.error('Get challenges error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/challenges', auth, authorize(['intern']), [
  body('title').trim().isLength({ min: 5 }).withMessage('Title must be at least 5 characters'),
  body('description').trim().isLength({ min: 20 }).withMessage('Description must be at least 20 characters'),
  body('task_id').optional().isInt().withMessage('Task ID must be a valid number')
], handleValidationErrors, async (req, res) => {
  try {
    const { title, description, task_id } = req.body;
    
    // If task_id provided, verify it belongs to the user
    if (task_id) {
      const [tasks] = await pool.execute(
        'SELECT id FROM tasks WHERE id = ? AND assigned_to = ?',
        [task_id, req.user.id]
      );
      
      if (!tasks.length) {
        return res.status(400).json({ error: 'Task not found or not assigned to you' });
      }
    }
    
    const [result] = await pool.execute(
      'INSERT INTO challenges (user_id, title, description, task_id) VALUES (?, ?, ?, ?)',
      [req.user.id, title, description, task_id]
    );
    
    res.status(201).json({ 
      message: 'Challenge logged successfully',
      challengeId: result.insertId
    });
  } catch (error) {
    console.error('Create challenge error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/challenges/:id/response', auth, authorize(['manager']), [
  body('response').trim().isLength({ min: 10 }).withMessage('Response must be at least 10 characters'),
  body('status').isIn(['resolved']).withMessage('Status must be resolved')
], handleValidationErrors, async (req, res) => {
  try {
    const { response, status } = req.body;
    const challengeId = req.params.id;
    
    // Check if challenge exists
    const [challenges] = await pool.execute(
      'SELECT * FROM challenges WHERE id = ?',
      [challengeId]
    );
    
    if (!challenges.length) {
      return res.status(404).json({ error: 'Challenge not found' });
    }
    
    if (challenges[0].status !== 'open') {
      return res.status(400).json({ error: 'Challenge is already resolved' });
    }
    
    await pool.execute(
      'UPDATE challenges SET response = ?, status = ? WHERE id = ?',
      [response, status, challengeId]
    );
    
    res.json({ message: 'Challenge response added successfully' });
  } catch (error) {
    console.error('Respond to challenge error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get users (for manager to assign tasks)
app.get('/api/users', auth, authorize(['manager']), async (req, res) => {
  try {
    const [users] = await pool.execute(
      'SELECT id, name, email, role, created_at FROM users WHERE role = "intern"'
    );
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});