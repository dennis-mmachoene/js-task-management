const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

const { connectDB } = require('./config/db');
const { auth, authorize } = require('./middleware/auth');

// Import models
const User = require('./models/User');
const Task = require('./models/Task');
const LeaveRequest = require('./models/LeaveRequest');
const Challenge = require('./models/Challenge');

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

// Connect to MongoDB
connectDB();

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
    const existingUser = await User.findOne({ email });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = new User({
      email,
      password: hashedPassword,
      name,
      role
    });
    
    await user.save();
    
    res.status(201).json({ 
      message: 'User created successfully', 
      userId: user._id 
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
    
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    res.json({
      token,
      user: {
        id: user._id,
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

// Task Routes with enhanced validation
app.get('/api/tasks', auth, async (req, res) => {
  try {
    const { status, priority, page = 1, limit = 10 } = req.query;

    const safePage = parseInt(page, 10) || 1;
    const safeLimit = parseInt(limit, 10) || 10;
    const skip = (safePage - 1) * safeLimit;

    let filter = {};

    if (req.user.role === 'intern') {
      filter.assignedTo = req.user._id;
    }

    if (status && status.trim()) {
      filter.status = status.trim();
    }

    if (priority && priority.trim()) {
      filter.priority = priority.trim();
    }

    console.log('MongoDB Filter:', filter);

    const tasks = await Task.find(filter)
      .populate('assignedTo', 'name')
      .populate('createdBy', 'name')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(safeLimit);

    const total = await Task.countDocuments(filter);

    // Transform the data to match the original response format
    const transformedTasks = tasks.map(task => ({
      id: task._id,
      title: task.title,
      description: task.description,
      status: task.status,
      priority: task.priority,
      assigned_to: task.assignedTo?._id,
      assigned_to_name: task.assignedTo?.name,
      created_by: task.createdBy?._id,
      created_by_name: task.createdBy?.name,
      due_date: task.dueDate,
      created_at: task.createdAt,
      updated_at: task.updatedAt
    }));

    res.json({
      tasks: transformedTasks,
      pagination: {
        page: safePage,
        limit: safeLimit,
        total,
        pages: Math.ceil(total / safeLimit),
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
  body('assigned_to').isMongoId().withMessage('Assigned user must be a valid user ID'),
  body('priority').isIn(['low', 'medium', 'high']).withMessage('Priority must be low, medium, or high'),
  body('due_date').optional().isISO8601().withMessage('Due date must be a valid date')
], handleValidationErrors, async (req, res) => {
  try {
    const { title, description, assigned_to, priority, due_date } = req.body;
    
    // Verify assigned user exists and is an intern
    const assignedUser = await User.findById(assigned_to);
    
    if (!assignedUser || assignedUser.role !== 'intern') {
      return res.status(400).json({ error: 'Can only assign tasks to interns' });
    }
    
    const task = new Task({
      title,
      description,
      assignedTo: assigned_to,
      createdBy: req.user._id,
      priority,
      dueDate: due_date
    });
    
    await task.save();
    
    res.status(201).json({ 
      message: 'Task created successfully', 
      taskId: task._id 
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
    
    if (!mongoose.Types.ObjectId.isValid(taskId)) {
      return res.status(400).json({ error: 'Invalid task ID' });
    }
    
    // Check if task exists and user has permission
    const task = await Task.findById(taskId);
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    // Interns can only update their own tasks
    if (req.user.role === 'intern' && !task.assignedTo.equals(req.user._id)) {
      return res.status(403).json({ error: 'Can only update your own tasks' });
    }
    
    task.status = status;
    await task.save();
    
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
    const skip = (safePage - 1) * safeLimit;

    let filter = {};
    
    if (req.user.role === 'intern') {
      filter.userId = req.user._id;
    }
    
    if (status) {
      filter.status = status;
    }
    
    const requests = await LeaveRequest.find(filter)
      .populate('userId', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(safeLimit);
    
    // Transform the data to match the original response format
    const transformedRequests = requests.map(request => ({
      id: request._id,
      user_id: request.userId._id,
      user_name: request.userId.name,
      user_email: request.userId.email,
      start_date: request.startDate,
      end_date: request.endDate,
      reason: request.reason,
      status: request.status,
      created_at: request.createdAt
    }));
    
    res.json(transformedRequests);
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
    const overlapping = await LeaveRequest.findOne({
      userId: req.user._id,
      status: 'approved',
      $or: [
        {
          startDate: { $lte: new Date(start_date) },
          endDate: { $gte: new Date(start_date) }
        },
        {
          startDate: { $lte: new Date(end_date) },
          endDate: { $gte: new Date(end_date) }
        }
      ]
    });
    
    if (overlapping) {
      return res.status(400).json({ error: 'You already have approved leave for these dates' });
    }
    
    const leaveRequest = new LeaveRequest({
      userId: req.user._id,
      startDate: start_date,
      endDate: end_date,
      reason
    });
    
    await leaveRequest.save();
    
    res.status(201).json({ 
      message: 'Leave request submitted successfully',
      requestId: leaveRequest._id
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
    
    if (!mongoose.Types.ObjectId.isValid(requestId)) {
      return res.status(400).json({ error: 'Invalid request ID' });
    }
    
    // Check if request exists
    const leaveRequest = await LeaveRequest.findById(requestId);
    
    if (!leaveRequest) {
      return res.status(404).json({ error: 'Leave request not found' });
    }
    
    if (leaveRequest.status !== 'pending') {
      return res.status(400).json({ error: 'Can only update pending requests' });
    }
    
    leaveRequest.status = status;
    await leaveRequest.save();
    
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
    const skip = (safePage - 1) * safeLimit;

    let filter = {};
    
    if (req.user.role === 'intern') {
      filter.userId = req.user._id;
    }
    
    if (status) {
      filter.status = status;
    }
    
    const challenges = await Challenge.find(filter)
      .populate('userId', 'name')
      .populate('taskId', 'title')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(safeLimit);
    
    // Transform the data to match the original response format
    const transformedChallenges = challenges.map(challenge => ({
      id: challenge._id,
      user_id: challenge.userId._id,
      user_name: challenge.userId.name,
      task_id: challenge.taskId?._id,
      task_title: challenge.taskId?.title,
      title: challenge.title,
      description: challenge.description,
      status: challenge.status,
      response: challenge.response,
      created_at: challenge.createdAt
    }));
    
    res.json(transformedChallenges);
  } catch (error) {
    console.error('Get challenges error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/challenges', auth, authorize(['intern']), [
  body('title').trim().isLength({ min: 5 }).withMessage('Title must be at least 5 characters'),
  body('description').trim().isLength({ min: 20 }).withMessage('Description must be at least 20 characters'),
  body('task_id').optional().isMongoId().withMessage('Task ID must be a valid ID')
], handleValidationErrors, async (req, res) => {
  try {
    const { title, description, task_id } = req.body;
    
    // If task_id provided, verify it belongs to the user
    if (task_id) {
      const task = await Task.findOne({ _id: task_id, assignedTo: req.user._id });
      
      if (!task) {
        return res.status(400).json({ error: 'Task not found or not assigned to you' });
      }
    }
    
    const challenge = new Challenge({
      userId: req.user._id,
      title,
      description,
      taskId: task_id || null
    });
    
    await challenge.save();
    
    res.status(201).json({ 
      message: 'Challenge logged successfully',
      challengeId: challenge._id
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
    
    if (!mongoose.Types.ObjectId.isValid(challengeId)) {
      return res.status(400).json({ error: 'Invalid challenge ID' });
    }
    
    // Check if challenge exists
    const challenge = await Challenge.findById(challengeId);
    
    if (!challenge) {
      return res.status(404).json({ error: 'Challenge not found' });
    }
    
    if (challenge.status !== 'open') {
      return res.status(400).json({ error: 'Challenge is already resolved' });
    }
    
    challenge.response = response;
    challenge.status = status;
    await challenge.save();
    
    res.json({ message: 'Challenge response added successfully' });
  } catch (error) {
    console.error('Respond to challenge error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get users (for manager to assign tasks)
app.get('/api/users', auth, authorize(['manager']), async (req, res) => {
  try {
    const users = await User.find({ role: 'intern' })
      .select('name email role createdAt')
      .sort({ createdAt: -1 });
    
    // Transform the data to match the original response format
    const transformedUsers = users.map(user => ({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      created_at: user.createdAt
    }));
    
    res.json(transformedUsers);
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