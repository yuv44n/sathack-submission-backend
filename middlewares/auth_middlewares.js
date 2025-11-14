import jwt from "jsonwebtoken";

/**
 * Middleware to verify JWT token from cookie
 * Attaches user info to req.user if valid
 */
export const verifyAuth = async (req, res, next) => {
  try {
    // Debug: Log cookie information (without sensitive data)
    console.log('[AUTH MIDDLEWARE] Cookies received:', {
      hasSessionCookie: !!req.cookies?.session,
      cookieNames: Object.keys(req.cookies || {}),
      headers: {
        cookie: req.headers.cookie ? 'present' : 'missing',
        origin: req.headers.origin,
        referer: req.headers.referer,
      },
    });

    // Get token from Authorization header (Bearer) or fallback to cookie
    const authHeader = req.headers.authorization || req.headers.Authorization;
    let token = null;
    if (authHeader && typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')) {
      token = authHeader.slice(7).trim();
    } else {
      token = req.cookies?.session;
    }

    if (!token) {
      return res.status(401).json({
        error: 'Unauthorized',
        details: 'No session token found. Please login first. Send as `Authorization: Bearer <token>` for localStorage flows.'
      });
    }

    // Verify JWT token
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error("[AUTH MIDDLEWARE] JWT_SECRET is not set in environment variables");
      return res.status(500).json({ 
        error: "Server configuration error",
        details: "JWT secret is not configured"
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, jwtSecret);
    } catch (error) {
      if (error.name === "JsonWebTokenError") {
        return res.status(401).json({ 
          error: "Unauthorized",
          details: "Invalid session token. Please login again."
        });
      }
      if (error.name === "TokenExpiredError") {
        return res.status(401).json({ 
          error: "Unauthorized",
          details: "Session token has expired. Please login again."
        });
      }
      throw error;
    }

    // Validate decoded token has required fields
    if (!decoded.uid || !decoded.teamId) {
      return res.status(401).json({ 
        error: "Unauthorized",
        details: "Invalid token payload. Please login again."
      });
    }

    // Attach user info to request object
    req.user = {
      uid: decoded.uid,
      email: decoded.email,
      leaderUserId: decoded.leaderUserId || decoded.uid,
      teamId: decoded.teamId,
    };

    next();
  } catch (error) {
    console.error("[AUTH MIDDLEWARE ERROR]:", error);
    next(error);
  }
};

