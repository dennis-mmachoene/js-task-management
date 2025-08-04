import React, { useState, useEffect, createContext, useContext } from 'react';
import { Calendar, CheckCircle, Clock, AlertTriangle, Plus, LogOut, User, FileText, Send, X, Eye, EyeOff } from 'lucide-react';

// Auth Context
const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.exp * 1000 > Date.now()) {
          fetchUserData();
        } else {
          logout();
        }
      } catch (e) {
        logout();
      }
    } else {
      setLoading(false);
    }
  }, [token]);

  const fetchUserData = async () => {
    try {
      const response = await fetch('https://task-management-cmad.onrender.com/api/tasks', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        const payload = JSON.parse(atob(token.split('.')[1]));
        setUser({ id: payload.userId, role: payload.role });
      } else {
        logout();
      }
    } catch (error) {
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = (userData, userToken) => {
    setUser(userData);
    setToken(userToken);
    localStorage.setItem('token', userToken);
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    setLoading(false);
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="spinner"></div>
      </div>
    );
  }

  return (
    <AuthContext.Provider value={{ user, token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => useContext(AuthContext);

// Toast Context for notifications
const ToastContext = createContext();

const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([]);

  const addToast = (message, type = 'info') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(toast => toast.id !== id));
    }, 5000);
  };

  const removeToast = (id) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  };

  return (
    <ToastContext.Provider value={{ addToast }}>
      {children}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {toasts.map(toast => (
          <div key={toast.id} className={`toast toast-${toast.type} animate-fade-in`}>
            <div className="flex justify-between items-start">
              <p className="text-sm font-medium">{toast.message}</p>
              <button
                onClick={() => removeToast(toast.id)}
                className="ml-2 text-gray-400 hover:text-gray-600"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

const useToast = () => useContext(ToastContext);

// API Service
class ApiService {
  static baseURL = 'https://task-management-cmad.onrender.com/api';

  static async request(endpoint, options = {}) {
    const token = localStorage.getItem('token');
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
      },
      ...options,
    };

    if (config.body && typeof config.body === 'object') {
      config.body = JSON.stringify(config.body);
    }

    const response = await fetch(`${this.baseURL}${endpoint}`, config);
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Network error' }));
      throw new Error(error.error || 'Something went wrong');
    }

    return response.json();
  }

  static async login(email, password) {
    return this.request('/login', {
      method: 'POST',
      body: { email, password },
    });
  }

  static async register(userData) {
    return this.request('/register', {
      method: 'POST',
      body: userData,
    });
  }

  static async getTasks(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    return this.request(`/tasks${queryString ? `?${queryString}` : ''}`);
  }

  static async createTask(taskData) {
    return this.request('/tasks', {
      method: 'POST',
      body: taskData,
    });
  }

  static async updateTaskStatus(taskId, status) {
    return this.request(`/tasks/${taskId}/status`, {
      method: 'PUT',
      body: { status },
    });
  }

  static async getLeaveRequests(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    return this.request(`/leave-requests${queryString ? `?${queryString}` : ''}`);
  }

  static async createLeaveRequest(leaveData) {
    return this.request('/leave-requests', {
      method: 'POST',
      body: leaveData,
    });
  }

  static async updateLeaveRequest(requestId, status) {
    return this.request(`/leave-requests/${requestId}`, {
      method: 'PUT',
      body: { status },
    });
  }

  static async getChallenges(params = {}) {
    const queryString = new URLSearchParams(params).toString();
    return this.request(`/challenges${queryString ? `?${queryString}` : ''}`);
  }

  static async createChallenge(challengeData) {
    return this.request('/challenges', {
      method: 'POST',
      body: challengeData,
    });
  }

  static async respondToChallenge(challengeId, response, status) {
    return this.request(`/challenges/${challengeId}/response`, {
      method: 'PUT',
      body: { response, status },
    });
  }

  static async getUsers() {
    return this.request('/users');
  }
}

// Login Component
const Login = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: '',
    role: 'intern'
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();
  const { addToast } = useToast();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (isLogin) {
        const response = await ApiService.login(formData.email, formData.password);
        login(response.user, response.token);
        addToast(`Welcome back, ${response.user.name}!`, 'success');
      } else {
        await ApiService.register(formData);
        setIsLogin(true);
        setFormData({ email: '', password: '', name: '', role: 'intern' });
        addToast('Registration successful! Please login.', 'success');
      }
    } catch (err) {
      setError(err.message);
      addToast(err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (error) setError('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-500 via-purple-500 to-indigo-600 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-2xl p-8 w-full max-w-md animate-fade-in">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-800 mb-2">Task Manager</h1>
          <h2 className="text-xl font-semibold text-gray-600">
            {isLogin ? 'Welcome Back' : 'Create Account'}
          </h2>
        </div>
        
        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 text-red-700 rounded-lg animate-fade-in">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          {!isLogin && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Full Name</label>
              <input
                type="text"
                className="form-input"
                value={formData.name}
                onChange={(e) => handleInputChange('name', e.target.value)}
                placeholder="Enter your full name"
                required
              />
            </div>
          )}
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Email Address</label>
            <input
              type="email"
              className="form-input"
              value={formData.email}
              onChange={(e) => handleInputChange('email', e.target.value)}
              placeholder="Enter your email"
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                className="form-input pr-10"
                value={formData.password}
                onChange={(e) => handleInputChange('password', e.target.value)}
                placeholder="Enter your password"
                required
              />
              <button
                type="button"
                className="absolute inset-y-0 right-0 pr-3 flex items-center"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? (
                  <EyeOff className="h-5 w-5 text-gray-400" />
                ) : (
                  <Eye className="h-5 w-5 text-gray-400" />
                )}
              </button>
            </div>
          </div>

          {!isLogin && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Role</label>
              <select
                className="form-select"
                value={formData.role}
                onChange={(e) => handleInputChange('role', e.target.value)}
              >
                <option value="intern">Intern</option>
                <option value="manager">Manager</option>
              </select>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full btn-primary flex items-center justify-center"
          >
            {loading ? (
              <div className="spinner mr-2"></div>
            ) : null}
            {loading ? 'Please wait...' : (isLogin ? 'Sign In' : 'Create Account')}
          </button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-gray-600">
            {isLogin ? "Don't have an account? " : "Already have an account? "}
            <button
              className="text-blue-600 hover:text-blue-800 font-medium"
              onClick={() => {
                setIsLogin(!isLogin);
                setError('');
                setFormData({ email: '', password: '', name: '', role: 'intern' });
              }}
            >
              {isLogin ? 'Sign up' : 'Sign in'}
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('tasks');
  const { addToast } = useToast();
  
  const handleLogout = () => {
    logout();
    addToast('Logged out successfully', 'info');
  };

  const tabs = [
    { key: 'tasks', label: 'Tasks', icon: CheckCircle },
    { key: 'leaves', label: 'Leaves', icon: Calendar },
    { key: 'challenges', label: 'Challenges', icon: AlertTriangle }
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Task Management System</h1>
              <p className="text-sm text-gray-600">
                Welcome back, {user?.role?.charAt(0).toUpperCase() + user?.role?.slice(1)}
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center text-sm text-gray-600 bg-gray-100 px-3 py-1 rounded-full">
                <User className="w-4 h-4 mr-2" />
                {user?.role?.charAt(0).toUpperCase() + user?.role?.slice(1)}
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center text-red-600 hover:text-red-700 transition-colors"
              >
                <LogOut className="w-4 h-4 mr-1" />
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <nav className="flex space-x-8 mb-8 border-b border-gray-200">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`nav-tab ${
                  activeTab === tab.key ? 'nav-tab-active' : 'nav-tab-inactive'
                }`}
              >
                <div className="flex items-center space-x-2">
                  <Icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </div>
              </button>
            );
          })}
        </nav>

        <div className="animate-fade-in">
          {activeTab === 'tasks' && <TasksSection />}
          {activeTab === 'leaves' && <LeavesSection />}
          {activeTab === 'challenges' && <ChallengesSection />}
        </div>
      </div>
    </div>
  );
};

// Tasks Section
const TasksSection = () => {
  const { user } = useAuth();
  const { addToast } = useToast();
  const [tasks, setTasks] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [filters, setFilters] = useState({
    status: '',
    priority: ''
  });

  useEffect(() => {
    fetchTasks();
    if (user?.role === 'manager') {
      fetchUsers();
    }
  }, [user, filters]);

  const fetchTasks = async () => {
    try {
      setLoading(true);
      const response = await ApiService.getTasks(filters);
      setTasks(response.tasks || response);
    } catch (error) {
      addToast('Error fetching tasks: ' + error.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const fetchUsers = async () => {
    try {
      const data = await ApiService.getUsers();
      setUsers(data);
    } catch (error) {
      addToast('Error fetching users: ' + error.message, 'error');
    }
  };

  const updateTaskStatus = async (taskId, newStatus) => {
    try {
      await ApiService.updateTaskStatus(taskId, newStatus);
      addToast('Task status updated successfully', 'success');
      fetchTasks();
    } catch (error) {
      addToast('Error updating task: ' + error.message, 'error');
    }
  };

  if (loading) {
    return (
      <div className="text-center py-12">
        <div className="spinner mx-auto mb-4"></div>
        <p className="text-gray-600">Loading tasks...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <h2 className="text-2xl font-bold text-gray-900">Tasks</h2>
        <div className="flex flex-col sm:flex-row gap-4 w-full sm:w-auto">
          {/* Filters */}
          <div className="flex gap-2">
            <select
              className="form-select text-sm"
              value={filters.status}
              onChange={(e) => setFilters({...filters, status: e.target.value})}
            >
              <option value="">All Status</option>
              <option value="pending">Pending</option>
              <option value="in_progress">In Progress</option>
              <option value="completed">Completed</option>
            </select>
            <select
              className="form-select text-sm"
              value={filters.priority}
              onChange={(e) => setFilters({...filters, priority: e.target.value})}
            >
              <option value="">All Priority</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
          </div>
          
          {user?.role === 'manager' && (
            <button
              onClick={() => setShowCreateForm(true)}
              className="btn-primary flex items-center whitespace-nowrap"
            >
              <Plus className="w-4 h-4 mr-2" />
              Create Task
            </button>
          )}
        </div>
      </div>

      {showCreateForm && (
        <CreateTaskForm
          users={users}
          onClose={() => setShowCreateForm(false)}
          onSuccess={() => {
            setShowCreateForm(false);
            fetchTasks();
          }}
        />
      )}

      {tasks.length === 0 ? (
        <div className="text-center py-12">
          <CheckCircle className="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <p className="text-gray-500 text-lg">No tasks found</p>
          <p className="text-gray-400 text-sm">
            {user?.role === 'manager' ? 'Create your first task to get started' : 'Your manager will assign tasks to you'}
          </p>
        </div>
      ) : (
        <div className="grid gap-4">
          {tasks.map((task) => (
            <TaskCard
              key={task.id}
              task={task}
              userRole={user?.role}
              onStatusUpdate={updateTaskStatus}
            />
          ))}
        </div>
      )}
    </div>
  );
};

// Task Card Component
const TaskCard = ({ task, userRole, onStatusUpdate }) => {
  const [isUpdating, setIsUpdating] = useState(false);

  const handleStatusUpdate = async (newStatus) => {
    setIsUpdating(true);
    try {
      await onStatusUpdate(task.id, newStatus);
    } finally {
      setIsUpdating(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'status-completed';
      case 'in_progress': return 'status-in-progress';
      default: return 'status-pending';
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'high': return 'priority-high';
      case 'medium': return 'priority-medium';
      default: return 'priority-low';
    }
  };

  return (
    <div className="card hover:shadow-lg transition-all duration-200">
      <div className="flex justify-between items-start mb-4">
        <h3 className="font-semibold text-lg text-gray-900">{task.title}</h3>
        <span className={`status-badge ${getPriorityColor(task.priority)}`}>
          {task.priority} priority
        </span>
      </div>
      
      {task.description && (
        <p className="text-gray-600 mb-4 leading-relaxed">{task.description}</p>
      )}
      
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4 text-sm text-gray-500">
          <span className="flex items-center">
            <User className="w-4 h-4 mr-1" />
            {task.assigned_to_name}
          </span>
          {task.due_date && (
            <span className="flex items-center">
              <Calendar className="w-4 h-4 mr-1" />
              {new Date(task.due_date).toLocaleDateString()}
            </span>
          )}
        </div>
        
        <div className="flex items-center space-x-3">
          <span className={`status-badge ${getStatusColor(task.status)}`}>
            {task.status.replace('_', ' ')}
          </span>
          
          {userRole === 'intern' && task.status !== 'completed' && (
            <div className="relative">
              <select
                value={task.status}
                onChange={(e) => handleStatusUpdate(e.target.value)}
                disabled={isUpdating}
                className="text-xs p-1 border rounded focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:opacity-50"
              >
                <option value="pending">Pending</option>
                <option value="in_progress">In Progress</option>
                <option value="completed">Completed</option>
              </select>
              {isUpdating && (
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="spinner w-3 h-3"></div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Create Task Form
const CreateTaskForm = ({ users, onClose, onSuccess }) => {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    assigned_to: '',
    priority: 'medium',
    due_date: ''
  });
  const [loading, setLoading] = useState(false);
  const { addToast } = useToast();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      await ApiService.createTask(formData);
      addToast('Task created successfully', 'success');
      onSuccess();
    } catch (error) {
      addToast('Error creating task: ' + error.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content p-6">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-xl font-semibold text-gray-900">Create New Task</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Task Title</label>
            <input
              type="text"
              className="form-input"
              value={formData.title}
              onChange={(e) => setFormData({...formData, title: e.target.value})}
              placeholder="Enter task title"
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Description</label>
            <textarea
              className="form-textarea"
              value={formData.description}
              onChange={(e) => setFormData({...formData, description: e.target.value})}
              placeholder="Enter task description"
              rows={3}
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Assign to Intern</label>
            <select
              className="form-select"
              value={formData.assigned_to}
              onChange={(e) => setFormData({...formData, assigned_to: e.target.value})}
              required
            >
              <option value="">Select an intern</option>
              {users.map(user => (
                <option key={user.id} value={user.id}>{user.name} ({user.email})</option>
              ))}
            </select>
          </div>
          
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Priority</label>
              <select
                className="form-select"
                value={formData.priority}
                onChange={(e) => setFormData({...formData, priority: e.target.value})}
              >
                <option value="low">Low Priority</option>
                <option value="medium">Medium Priority</option>
                <option value="high">High Priority</option>
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Due Date</label>
              <input
                type="date"
                className="form-input"
                value={formData.due_date}
                onChange={(e) => setFormData({...formData, due_date: e.target.value})}
                min={new Date().toISOString().split('T')[0]}
              />
            </div>
          </div>
          
          <div className="flex space-x-4 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 btn-primary"
            >
              {loading ? (
                <div className="flex items-center justify-center">
                  <div className="spinner mr-2"></div>
                  Creating...
                </div>
              ) : (
                'Create Task'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Leaves Section
const LeavesSection = () => {
  const { user } = useAuth();
  const { addToast } = useToast();
  const [leaveRequests, setLeaveRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    fetchLeaveRequests();
  }, [filter]);

  const fetchLeaveRequests = async () => {
    try {
      setLoading(true);
      const params = filter ? { status: filter } : {};
      const data = await ApiService.getLeaveRequests(params);
      setLeaveRequests(data);
    } catch (error) {
      addToast('Error fetching leave requests: ' + error.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const updateLeaveStatus = async (requestId, status) => {
    try {
      await ApiService.updateLeaveRequest(requestId, status);
      addToast(`Leave request ${status} successfully`, 'success');
      fetchLeaveRequests();
    } catch (error) {
      addToast('Error updating leave request: ' + error.message, 'error');
    }
  };

  if (loading) {
    return (
      <div className="text-center py-12">
        <div className="spinner mx-auto mb-4"></div>
        <p className="text-gray-600">Loading leave requests...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <h2 className="text-2xl font-bold text-gray-900">Leave Requests</h2>
        <div className="flex gap-4 w-full sm:w-auto">
          <select
            className="form-select text-sm"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="">All Requests</option>
            <option value="pending">Pending</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
          </select>
          
          {user?.role === 'intern' && (
            <button
              onClick={() => setShowCreateForm(true)}
              className="btn-primary flex items-center whitespace-nowrap"
            >
              <Plus className="w-4 h-4 mr-2" />
              Request Leave
            </button>
          )}
        </div>
      </div>

      {showCreateForm && (
        <CreateLeaveForm
          onClose={() => setShowCreateForm(false)}
          onSuccess={() => {
            setShowCreateForm(false);
            fetchLeaveRequests();
          }}
        />
      )}

      {leaveRequests.length === 0 ? (
        <div className="text-center py-12">
          <Calendar className="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <p className="text-gray-500 text-lg">No leave requests found</p>
          <p className="text-gray-400 text-sm">
            {user?.role === 'intern' ? 'Submit your first leave request' : 'No leave requests to review'}
          </p>
        </div>
      ) : (
        <div className="grid gap-4">
          {leaveRequests.map((request) => (
            <LeaveCard
              key={request.id}
              request={request}
              userRole={user?.role}
              onStatusUpdate={updateLeaveStatus}
            />
          ))}
        </div>
      )}
    </div>
  );
};

// Leave Card Component
const LeaveCard = ({ request, userRole, onStatusUpdate }) => {
  const [isUpdating, setIsUpdating] = useState(false);

  const handleStatusUpdate = async (status) => {
    setIsUpdating(true);
    try {
      await onStatusUpdate(request.id, status);
    } finally {
      setIsUpdating(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'approved': return 'status-approved';
      case 'rejected': return 'status-rejected';
      default: return 'status-pending';
    }
  };

  const calculateDays = (startDate, endDate) => {
    const start = new Date(startDate);
    const end = new Date(endDate);
    const diffTime = Math.abs(end - start);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;
    return diffDays;
  };

  return (
    <div className="card">
      <div className="flex justify-between items-start mb-4">
        <div>
          <h3 className="font-semibold text-lg text-gray-900">
            {userRole === 'manager' ? `${request.user_name}'s Leave Request` : 'Your Leave Request'}
          </h3>
          <p className="text-gray-600 mt-1">{request.reason}</p>
        </div>
        <span className={`status-badge ${getStatusColor(request.status)}`}>
          {request.status}
        </span>
      </div>
      
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-6 text-sm text-gray-500">
          <span className="flex items-center">
            <Calendar className="w-4 h-4 mr-1" />
            {new Date(request.start_date).toLocaleDateString()} - {new Date(request.end_date).toLocaleDateString()}
          </span>
          <span className="flex items-center">
            <Clock className="w-4 h-4 mr-1" />
            {calculateDays(request.start_date, request.end_date)} day(s)
          </span>
        </div>
        
        {userRole === 'manager' && request.status === 'pending' && (
          <div className="flex space-x-2">
            <button
              onClick={() => handleStatusUpdate('approved')}
              disabled={isUpdating}
              className="btn-success text-sm px-3 py-1 disabled:opacity-50"
            >
              {isUpdating ? <div className="spinner w-3 h-3"></div> : 'Approve'}
            </button>
            <button
              onClick={() => handleStatusUpdate('rejected')}
              disabled={isUpdating}
              className="btn-danger text-sm px-3 py-1 disabled:opacity-50"
            >
              {isUpdating ? <div className="spinner w-3 h-3"></div> : 'Reject'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

// Create Leave Form
const CreateLeaveForm = ({ onClose, onSuccess }) => {
  const [formData, setFormData] = useState({
    start_date: '',
    end_date: '',
    reason: ''
  });
  const [loading, setLoading] = useState(false);
  const { addToast } = useToast();

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validation
    if (new Date(formData.start_date) >= new Date(formData.end_date)) {
      addToast('End date must be after start date', 'error');
      return;
    }
    
    if (new Date(formData.start_date) < new Date()) {
      addToast('Start date cannot be in the past', 'error');
      return;
    }

    setLoading(true);
    
    try {
      await ApiService.createLeaveRequest(formData);
      addToast('Leave request submitted successfully', 'success');
      onSuccess();
    } catch (error) {
      addToast('Error submitting leave request: ' + error.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const today = new Date().toISOString().split('T')[0];

  return (
    <div className="modal-overlay">
      <div className="modal-content p-6">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-xl font-semibold text-gray-900">Request Leave</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Start Date</label>
              <input
                type="date"
                className="form-input"
                value={formData.start_date}
                onChange={(e) => setFormData({...formData, start_date: e.target.value})}
                min={today}
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">End Date</label>
              <input
                type="date"
                className="form-input"
                value={formData.end_date}
                onChange={(e) => setFormData({...formData, end_date: e.target.value})}
                min={formData.start_date || today}
                required
              />
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Reason for Leave</label>
            <textarea
              className="form-textarea"
              value={formData.reason}
              onChange={(e) => setFormData({...formData, reason: e.target.value})}
              placeholder="Please provide a reason for your leave request"
              rows={4}
              required
            />
          </div>
          
          <div className="flex space-x-4 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 btn-primary"
            >
              {loading ? (
                <div className="flex items-center justify-center">
                  <div className="spinner mr-2"></div>
                  Submitting...
                </div>
              ) : (
                'Submit Request'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Challenges Section
const ChallengesSection = () => {
  const { user } = useAuth();
  const { addToast } = useToast();
  const [challenges, setChallenges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [responseForm, setResponseForm] = useState({ id: null, response: '' });
  const [filter, setFilter] = useState('');

  useEffect(() => {
    fetchChallenges();
  }, [filter]);

  const fetchChallenges = async () => {
    try {
      setLoading(true);
      const params = filter ? { status: filter } : {};
      const data = await ApiService.getChallenges(params);
      setChallenges(data);
    } catch (error) {
      addToast('Error fetching challenges: ' + error.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const respondToChallenge = async (challengeId, response) => {
    if (!response.trim()) {
      addToast('Please enter a response', 'error');
      return;
    }

    try {
      await ApiService.respondToChallenge(challengeId, response, 'resolved');
      setResponseForm({ id: null, response: '' });
      addToast('Challenge response sent successfully', 'success');
      fetchChallenges();
    } catch (error) {
      addToast('Error responding to challenge: ' + error.message, 'error');
    }
  };

  if (loading) {
    return (
      <div className="text-center py-12">
        <div className="spinner mx-auto mb-4"></div>
        <p className="text-gray-600">Loading challenges...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <h2 className="text-2xl font-bold text-gray-900">Challenges</h2>
        <div className="flex gap-4 w-full sm:w-auto">
          <select
            className="form-select text-sm"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="">All Challenges</option>
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
          </select>
          
          {user?.role === 'intern' && (
            <button
              onClick={() => setShowCreateForm(true)}
              className="btn-primary flex items-center whitespace-nowrap"
            >
              <Plus className="w-4 h-4 mr-2" />
              Log Challenge
            </button>
          )}
        </div>
      </div>

      {showCreateForm && (
        <CreateChallengeForm
          onClose={() => setShowCreateForm(false)}
          onSuccess={() => {
            setShowCreateForm(false);
            fetchChallenges();
          }}
        />
      )}

      {challenges.length === 0 ? (
        <div className="text-center py-12">
          <AlertTriangle className="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <p className="text-gray-500 text-lg">No challenges found</p>
          <p className="text-gray-400 text-sm">
            {user?.role === 'intern' ? 'Log a challenge when you need help' : 'No challenges to review'}
          </p>
        </div>
      ) : (
        <div className="grid gap-4">
          {challenges.map((challenge) => (
            <ChallengeCard
              key={challenge.id}
              challenge={challenge}
              userRole={user?.role}
              responseForm={responseForm}
              setResponseForm={setResponseForm}
              onRespond={respondToChallenge}
            />
          ))}
        </div>
      )}
    </div>
  );
};

// Challenge Card Component
const ChallengeCard = ({ challenge, userRole, responseForm, setResponseForm, onRespond }) => {
  const [isResponding, setIsResponding] = useState(false);

  const handleRespond = async () => {
    setIsResponding(true);
    try {
      await onRespond(challenge.id, responseForm.response);
    } finally {
      setIsResponding(false);
    }
  };

  const getStatusColor = (status) => {
    return status === 'resolved' ? 'status-resolved' : 'status-open';
  };

  return (
    <div className="card">
      <div className="flex justify-between items-start mb-4">
        <div className="flex-1">
          <h3 className="font-semibold text-lg text-gray-900">{challenge.title}</h3>
          <p className="text-gray-600 mt-2 leading-relaxed">{challenge.description}</p>
          {challenge.task_title && (
            <p className="text-sm text-blue-600 mt-2 flex items-center">
              <FileText className="w-4 h-4 mr-1" />
              Related Task: {challenge.task_title}
            </p>
          )}
        </div>
        <span className={`status-badge ${getStatusColor(challenge.status)} ml-4`}>
          {challenge.status}
        </span>
      </div>
      
      {challenge.response && (
        <div className="bg-blue-50 border-l-4 border-blue-400 p-4 mb-4">
          <p className="text-sm font-medium text-blue-800 mb-1">Manager Response:</p>
          <p className="text-sm text-blue-700">{challenge.response}</p>
        </div>
      )}
      
      <div className="flex items-center justify-between">
        <div className="text-sm text-gray-500">
          <span className="flex items-center">
            <User className="w-4 h-4 mr-1" />
            {userRole === 'manager' ? `By: ${challenge.user_name}` : 'Your Challenge'}
            <span className="mx-2">•</span>
            {new Date(challenge.created_at).toLocaleDateString()}
          </span>
        </div>
        
        {userRole === 'manager' && challenge.status === 'open' && (
          <div className="flex items-center space-x-2">
            {responseForm.id === challenge.id ? (
              <div className="flex items-center space-x-2">
                <input
                  type="text"
                  placeholder="Type your response..."
                  className="form-input text-sm min-w-[200px]"
                  value={responseForm.response}
                  onChange={(e) => setResponseForm({...responseForm, response: e.target.value})}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter' && responseForm.response.trim()) {
                      handleRespond();
                    }
                  }}
                />
                <button
                  onClick={handleRespond}
                  disabled={!responseForm.response.trim() || isResponding}
                  className="btn-primary text-sm px-3 py-1 disabled:opacity-50"
                >
                  {isResponding ? (
                    <div className="spinner w-3 h-3"></div>
                  ) : (
                    <Send className="w-4 h-4" />
                  )}
                </button>
                <button
                  onClick={() => setResponseForm({ id: null, response: '' })}
                  className="btn-secondary text-sm px-3 py-1"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => setResponseForm({ id: challenge.id, response: '' })}
                className="btn-primary text-sm px-3 py-1"
              >
                Respond
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

// Create Challenge Form
const CreateChallengeForm = ({ onClose, onSuccess }) => {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    task_id: ''
  });
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(false);
  const { addToast } = useToast();

  useEffect(() => {
    fetchTasks();
  }, []);

  const fetchTasks = async () => {
    try {
      const response = await ApiService.getTasks();
      setTasks(response.tasks || response);
    } catch (error) {
      addToast('Error fetching tasks: ' + error.message, 'error');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      await ApiService.createChallenge(formData);
      addToast('Challenge logged successfully', 'success');
      onSuccess();
    } catch (error) {
      addToast('Error logging challenge: ' + error.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content p-6">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-xl font-semibold text-gray-900">Log Challenge</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Challenge Title</label>
            <input
              type="text"
              className="form-input"
              value={formData.title}
              onChange={(e) => setFormData({...formData, title: e.target.value})}
              placeholder="Brief description of the challenge"
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Detailed Description</label>
            <textarea
              className="form-textarea"
              value={formData.description}
              onChange={(e) => setFormData({...formData, description: e.target.value})}
              placeholder="Describe the challenge you're facing in detail..."
              rows={4}
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Related Task (Optional)</label>
            <select
              className="form-select"
              value={formData.task_id}
              onChange={(e) => setFormData({...formData, task_id: e.target.value})}
            >
              <option value="">Select a related task (optional)</option>
              {tasks.map(task => (
                <option key={task.id} value={task.id}>{task.title}</option>
              ))}
            </select>
          </div>
          
          <div className="flex space-x-4 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 btn-primary"
            >
              {loading ? (
                <div className="flex items-center justify-center">
                  <div className="spinner mr-2"></div>
                  Logging...
                </div>
              ) : (
                'Log Challenge'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Main App Component
const App = () => {
  return (
    <AuthProvider>
      <ToastProvider>
        <AppContent />
      </ToastProvider>
    </AuthProvider>
  );
};

const AppContent = () => {
  const { user } = useAuth();

  return (
    <div className="App">
      {user ? <Dashboard /> : <Login />}
    </div>
  );
};

export default App;
