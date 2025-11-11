import jwt from "jsonwebtoken";

/**
 * Middleware to verify JWT token from cookie
 * Attaches user info to req.user if valid
 */
export const verifyAuth = async (req, res, next) => {
  try {
    // Get token from cookie
    const token = req.cookies?.session;

    if (!token) {
      return res.status(401).json({ 
        error: "Unauthorized",
        details: "No session token found. Please login first."
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

