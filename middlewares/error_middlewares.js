/**
 * Global error handling middleware
 * Catches all errors and sends appropriate responses
 */
export const errorHandler = (err, req, res, next) => {
  console.error('[ERROR HANDLER]:', err);

  // Handle specific error types
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation error',
      details: err.message,
    });
  }

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({
      error: 'Unauthorized',
      details: err.message,
    });
  }

  // Handle Google Sheets API errors
  if (err.message && err.message.includes('Access denied')) {
    return res.status(403).json({
      error: 'Access denied',
      details: err.message,
    });
  }

  if (err.message && err.message.includes('spreadsheet not found')) {
    return res.status(404).json({
      error: 'Spreadsheet not found',
      details: err.message,
    });
  }

  if (err.code === 'ECONNREFUSED') {
    return res.status(503).json({
      error: 'Service unavailable',
      details: 'External service connection failed. Please try again later.',
    });
  }

  // Handle Firebase errors
  if (err.code && err.code.startsWith('auth/')) {
    return res.status(401).json({
      error: 'Authentication error',
      details: err.message,
    });
  }

  // Handle Firestore errors
  if (err.code && err.code.startsWith('firestore/')) {
    return res.status(500).json({
      error: 'Database error',
      details: 'An error occurred while accessing the database. Please try again.',
    });
  }

  // Default error response
  const statusCode = err.status || err.statusCode || 500;
  return res.status(statusCode).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { 
      stack: err.stack,
      code: err.code,
    }),
  });
};

/**
 * 404 handler for undefined routes
 */
export const notFoundHandler = (req, res) => {
  return res.status(404).json({
    error: 'Route not found',
    path: req.path,
    method: req.method,
  });
};

