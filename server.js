import express from 'express'
import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import hpp from 'hpp';
dotenv.config();

import './firebase.js';
import { userRoutres } from './routes/user_routes.js';
import { errorHandler, notFoundHandler } from './middlewares/error_middlewares.js';

const app = express()

// Disable x-powered-by header
app.disable('x-powered-by');

// Trust proxy in production (needed for secure cookies and rate limiting behind proxies)
if (process.env.NODE_ENV === 'production') {
	app.set('trust proxy', 1);
}

// Basic health
app.get('/', (req, res) => {
  res.send('Hello World!')
});

const PORT = process.env.PORT || 8000

// Security: Helmet
app.use(helmet({
	crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// Request size limits and parsing
app.use(express.json({ limit: '100kb', type: ['application/json', 'application/*+json'] }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(cookieParser());

// Prevent HTTP Parameter Pollution
app.use(hpp());

// CORS (tightened)
const allowedOrigin = process.env.CLIENT_ORIGIN || 'http://localhost:5173';
app.use(cors({
	origin: [process.env.CLIENT_ORIGIN, 'http://localhost:5173'],
	credentials: true,
	methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
	allowedHeaders: ['Content-Type','Authorization','X-Requested-With','X-CSRF-Token'],
}));

// Anti-CSRF: validate Origin for state-changing requests (production only)
if (process.env.NODE_ENV === 'production') {
	app.use((req, res, next) => {
		const method = req.method.toUpperCase();
		if (['POST','PUT','PATCH','DELETE'].includes(method)) {
			const origin = req.headers.origin;
			if (origin && origin !== allowedOrigin) {
				return res.status(403).json({ error: 'Forbidden: invalid origin' });
			}
		}
		next();
	});
}

// Rate limiting (per IP)
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: Number(process.env.RATE_LIMIT_MAX || 200), // max requests per window per IP
	standardHeaders: true,
	legacyHeaders: false,
	message: { error: 'Too many requests, please try again later.' },
});
app.use('/api/', limiter);

// Routes
app.use('/api/users', userRoutres);

// Error handling middleware (must be after routes)
app.use(notFoundHandler);
app.use(errorHandler);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
})