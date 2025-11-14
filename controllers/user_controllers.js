import { auth, firestore } from "../firebase.js";
import jwt from "jsonwebtoken";
import { format } from "date-fns";
import {
  findRowByTeamId,
  addRowToSheet,
  getSubmissionByTeamId,
} from "../lib/googleSheets.js";

export const authenticateUser = async (req, res, next) => {
  try {
    const { uid, email } = req.body;

    // Validate required parameters
    if (!uid || !email) {
      return res.status(400).json({ 
        error: "Missing required fields",
        details: ["uid and email are required"]
      });
    }

    // Validate types
    if (typeof uid !== 'string' || typeof email !== 'string') {
      return res.status(400).json({
        error: "Invalid input types",
        details: ["uid and email must be strings"]
      });
    }

    // Sanitize inputs (trim and limit length)
    const sanitizedUid = uid.trim().slice(0, 128);
    const sanitizedEmail = email.trim().toLowerCase().slice(0, 255);

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitizedEmail)) {
      return res.status(400).json({
        error: "Invalid email format",
        details: ["email must be a valid email address"]
      });
    }

    // Validate UID format (Firebase UIDs are typically 28 characters)
    if (sanitizedUid.length < 10 || sanitizedUid.length > 128) {
      return res.status(400).json({
        error: "Invalid UID format",
        details: ["uid must be between 10 and 128 characters"]
      });
    }

    // Verify user exists in Firebase Auth (use sanitized values)
    let userRecord;
    try {
      userRecord = await auth.getUser(sanitizedUid);
    } catch (error) {
      return res.status(401).json({ error: "Invalid user: User not found in Firebase Auth" });
    }

    // Verify email matches (case-insensitive, use sanitized email)
    if (userRecord.email?.toLowerCase() !== sanitizedEmail) {
      return res.status(401).json({ error: "Email does not match the user record" });
    }

    console.log("[AUTH] Verifying user:", sanitizedUid, sanitizedEmail);

    // Check Firestore if user is team leader (use sanitized UID)
    const teamRegistrationQuery = await firestore
      .collection("teamRegistrations")
      .where("leaderUserId", "==", sanitizedUid)
      .limit(1)
      .get();

    if (teamRegistrationQuery.empty) {
      return res.status(403).json({
        error: "Only team leaders are allowed to login",
      });
    }

    console.log("[AUTH] User is a team leader:", uid, email);

    // Get team registration data
    const teamDoc = teamRegistrationQuery.docs[0];
    const teamData = teamDoc.data();
    const teamId = teamData.teamId || teamDoc.id; // Use teamId field if exists, otherwise use document ID

    const teamStatus = teamData?.status 

    if (teamStatus !== "confirmed" ) {
      return res.status(403).json({
        error: "Registration not confirmed yet!",
        details: ["Only confirmed teams can login"],
      });
    }

    // Generate JWT session token (use sanitized values)
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error("[AUTH] JWT_SECRET is not set in environment variables");
      return res.status(500).json({ error: "Server configuration error" });
    }
    
    const expiresIn = 60 * 60 * 24; // 24 hours in seconds
    const token = jwt.sign(
      {
        uid: sanitizedUid,
        email: sanitizedEmail,
        leaderUserId: sanitizedUid,
        teamId: teamId,
      },
      jwtSecret,
      { expiresIn }
    );

    // Set cookie with session token (secure settings)
    // Automatically detect cross-origin by comparing request origin with backend host
    const isProduction = process.env.NODE_ENV === "production";
    const requestOrigin = req.headers.origin;
    
    // Get backend URL (handle proxy scenarios)
    const backendHost = req.get('host') || req.hostname;
    const forwardedProto = req.headers['x-forwarded-proto'];
    const backendProtocol = forwardedProto || req.protocol || (req.secure ? 'https' : 'http');
    const backendUrl = `${backendProtocol}://${backendHost}`;
    
    // Check if request is cross-origin (different domain)
    // Also check if explicitly set via env var
    const isExplicitCrossOrigin = process.env.COOKIE_SAME_SITE === "none";
    let isAutoDetectedCrossOrigin = false;
    
    if (requestOrigin) {
      try {
        const originHostname = new URL(requestOrigin).hostname;
        const backendHostname = new URL(backendUrl).hostname;
        isAutoDetectedCrossOrigin = originHostname !== backendHostname;
      } catch (e) {
        // If URL parsing fails, check simple string comparison
        isAutoDetectedCrossOrigin = requestOrigin !== backendUrl && 
                                    !requestOrigin.includes(backendHost);
      }
    }
    
    const isCrossOrigin = isExplicitCrossOrigin || isAutoDetectedCrossOrigin;
    
    // Determine if request is over HTTPS
    const isHttps = req.secure || 
                    req.protocol === 'https' || 
                    forwardedProto === 'https' ||
                    (requestOrigin && requestOrigin.startsWith('https://'));
    
    // For cross-origin: MUST use sameSite: "none" with secure: true (HTTPS required)
    // For same-origin: use sameSite: "strict" (production) or "lax" (development)
    const cookieOptions = {
      httpOnly: true, // Prevents XSS attacks
      secure: isCrossOrigin ? true : (isProduction || isHttps), // Must be true for cross-origin
      sameSite: isCrossOrigin ? "none" : (isProduction ? "strict" : "lax"), // CSRF protection
      maxAge: expiresIn * 1000, // Convert to milliseconds
      path: "/", // Cookie available for all paths
      // For cross-origin: DO NOT set domain (let browser handle it)
      // For same-origin subdomains: set domain if provided
      ...(process.env.COOKIE_DOMAIN && !isCrossOrigin && { domain: process.env.COOKIE_DOMAIN }),
    };

    // For localStorage flows return the token in the response body so the
    // client can store it in localStorage and send it as
    // `Authorization: Bearer <token>` on subsequent requests.
    console.log('[AUTH] Generated JWT for user (not setting cookie for localStorage flow)');

    return res.status(200).json({
      message: 'Login successful',
      uid: sanitizedUid,
      email: sanitizedEmail,
      teamId: teamId,
      token: token,
      expiresIn: expiresIn,
    });

  } catch (error) {
    console.error("[AUTH ERROR]:", error);
    next(error);
  }
}

/**
 * Get team registration document for the authenticated leader
 * Protected route - requires valid JWT cookie
 */
export const getTeamRegistration = async (req, res, next) => {
  try {
    // User info is attached by verifyAuth middleware
    const { leaderUserId } = req.user;

    if (!leaderUserId) {
      return res.status(401).json({ 
        error: "Unauthorized: Invalid user session" 
      });
    }

    console.log("[ABOUT] Fetching team registration for leader:", leaderUserId);

    // Get team registration document from Firestore
    const teamRegistrationQuery = await firestore
      .collection("teamRegistrations")
      .where("leaderUserId", "==", leaderUserId)
      .limit(1)
      .get();

    if (teamRegistrationQuery.empty) {
      return res.status(404).json({
        error: "Team registration not found for this leader",
      });
    }

    // Get the complete document data
    const doc = teamRegistrationQuery.docs[0];
    const teamData = {
      id: doc.id,
      ...doc.data(),
    };

    console.log("[ABOUT] Team registration found:", doc.id);

    return res.status(200).json({
      message: "Team registration retrieved successfully",
      data: teamData,
    });

  } catch (error) {
    console.error("[ABOUT ERROR]:", error);
    next(error);
  }
}

/**
 * Submit team data to Google Sheets
 * Protected route - requires valid JWT cookie
 * If teamId already exists, returns previous entry
 * Otherwise, stores the new submission
 * Only accepts: githubLink, pptLink, videoLink, description
 * Fetches team data and leader info from Firestore
 */
export const submitTeamData = async (req, res, next) => {
  try {
    // User info is attached by verifyAuth middleware
    const { teamId, uid } = req.user;

    if (!uid) {
      return res.status(401).json({ 
        error: "Unauthorized: User ID not found in session" 
      });
    }

    // Get submission data from request body (only these 4 fields)
    const {
      githubLink,
      pptLink,
      videoLink,
      description,
    } = req.body;

    // Fetch team registration data from Firestore
    const teamRegistrationQuery = await firestore
      .collection("teamRegistrations")
      .where("leaderUserId", "==", uid)
      .limit(1)
      .get();

    if (teamRegistrationQuery.empty) {
      return res.status(404).json({
        error: "Team registration not found",
      });
    }

    const teamDoc = teamRegistrationQuery.docs[0];
    const teamData = teamDoc.data();

    // Get leader info from members[0] (leader is always first in members array)
    const leader = teamData.members && teamData.members.length > 0 
      ? teamData.members[0] 
      : null;

    if (!leader) {
      return res.status(404).json({
        error: "Leader information not found in team data",
      });
    }

    // Extract team information
    const teamName = teamData.teamName || '';
    const teamIdFromDB = teamData.teamId || teamDoc.id;
    const leaderName = leader.name || '';
    const leaderPhone = leader.phoneNumber || '';
    const leaderEmail = leader.email || '';

    // Check if teamId already exists in the sheet
    const existingSubmission = await findRowByTeamId(teamIdFromDB);

    if (existingSubmission) {
      // TeamId exists, return previous entry
      console.log("[SUBMIT] TeamId already exists, returning previous entry");
      return res.status(200).json({
        message: "Team submission already exists",
        data: existingSubmission.data,
        isExisting: true,
      });
    }

    // Generate submission time in a readable format
    // Format: "YYYY-MM-DD HH:mm:ss" (e.g., "2024-01-15 14:30:45")
    const submissionTime = format(new Date(), "yyyy-MM-dd HH:mm:ss");

    // Prepare submission data with all required fields
    const submissionData = {
      submissionTime,
      teamName,
      teamId: teamIdFromDB,
      leaderName,
      leaderPhone,
      leaderEmail,
      githubLink,
      pptLink,
      videoLink,
      description,
    };

    // Add to Google Sheets
    await addRowToSheet(submissionData);

    console.log("[SUBMIT] New submission added for teamId:", teamIdFromDB, "at", submissionTime);

    return res.status(201).json({
      message: "Team data submitted successfully",
      data: submissionData,
      isExisting: false,
    });

  } catch (error) {
    console.error("[SUBMIT ERROR]:", error);
    next(error);
  }
}

/**
 * Get submission data from Google Sheets
 * Protected route - requires valid JWT cookie
 * Used by useEffect hook to check if submission already exists
 */
export const getSubmission = async (req, res, next) => {
  try {
    // User info is attached by verifyAuth middleware
    const { uid } = req.user;

    if (!uid) {
      return res.status(401).json({ 
        error: "Unauthorized: User ID not found in session" 
      });
    }

    // Fetch team registration data from Firestore to get the correct teamId
    const teamRegistrationQuery = await firestore
      .collection("teamRegistrations")
      .where("leaderUserId", "==", uid)
      .limit(1)
      .get();

    if (teamRegistrationQuery.empty) {
      return res.status(404).json({
        error: "Team registration not found",
      });
    }

    const teamDoc = teamRegistrationQuery.docs[0];
    const teamData = teamDoc.data();
    const teamIdFromDB = teamData.teamId || teamDoc.id;

    console.log("[GET SUBMISSION] Fetching submission for teamId:", teamIdFromDB);

    // Get submission from Google Sheets using teamId from Firestore
    const submission = await getSubmissionByTeamId(teamIdFromDB);

    if (!submission) {
      return res.status(200).json({
        message: "No submission found for this team",
        data: null,
        hasSubmission: false,
      });
    }

    console.log("[GET SUBMISSION] Submission found for teamId:", teamIdFromDB);

    return res.status(200).json({
      message: "Submission retrieved successfully",
      data: submission,
      hasSubmission: true,
    });

  } catch (error) {
    console.error("[GET SUBMISSION ERROR]:", error);
    next(error);
  }
}

/**
 * Logout route - clears the session cookie
 */
export const logoutUser = async (req, res, next) => {
  try {
    // For localStorage-based auth, logout is performed client-side by removing
    // the token from localStorage. We still return a success response so the
    // client can clear its stored token.
    console.log('[LOGOUT] Logout requested - instruct client to remove token from localStorage');

    return res.status(200).json({
      message: 'Logged out successfully',
      note: 'Please remove the stored token from localStorage on the client.',
    });

  } catch (error) {
    console.error("[LOGOUT ERROR]:", error);
    next(error);
  }
}