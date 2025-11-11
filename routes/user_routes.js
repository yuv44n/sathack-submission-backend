import { Router } from "express";
import {
  authenticateUser,
  getTeamRegistration,
  submitTeamData,
  getSubmission,
  logoutUser,
} from "../controllers/user_controllers.js";
import { verifyAuth } from "../middlewares/auth_middlewares.js";
import { validateSubmission } from "../middlewares/validation_middlewares.js";

const userRoutres = Router();

// Public routes
userRoutres.post("/auth", authenticateUser);
userRoutres.post("/logout", logoutUser);

// Protected routes (require authentication)
userRoutres.get("/about", verifyAuth, getTeamRegistration);
userRoutres.get("/submission", verifyAuth, getSubmission);

// Protected route with validation (require authentication + validation)
userRoutres.post("/submit", verifyAuth, validateSubmission, submitTeamData);

export { userRoutres };