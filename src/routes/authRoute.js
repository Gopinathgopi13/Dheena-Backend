import { Router } from "express";
import authController from "../controllers/authController.js";

const authRouter = Router();

// User Login
authRouter.post("/login", authController.login);

authRouter.get("/logout", authController.logout);

authRouter.get("/refresh-token", authController.refreshToken);

// User registration
authRouter.post("/register", authController.createUser);

// if user forgot password
authRouter.post("/forgot-password", authController.forgot);

// To reset passwords
authRouter.post("/reset-Password", authController.resetPassword);

// Routing for verify mail account
authRouter.get("/verify-email", authController.verifyMail);

authRouter.post("/google", authController.google);

authRouter.post("/github", authController.github);

authRouter.post("/microsoft", authController.microsoft);

export default authRouter;
