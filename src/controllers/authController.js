import logger from "../loaders/logger.js";
import * as AuthService from "../services/authService.js";

const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const response = await AuthService.localLogin({ email, password });
    logger.info("User Logged in successfully.");
    res.status(200).json({
      message: "User Logged in successfully.",
      data: response,
      status: 1,
    });
  } catch (err) {
    logger.error("Login Error", err);
    res.status(401).json({ status: 0, message: err.message });
  }
};

const logout = (req, res) => {
  req.logout();
  res.status(200).json({ status: 1, message: "Logged out successfully" });
};

// Create Users
const createUser = async (req, res) => {
  try {
    const response = await AuthService.register(req.body);
    logger.info(response);

    res.status(201).json({
      status: 1,
      message: "User created successfull",
    });
  } catch (error) {
    if (error.message === "This email is already registered") {
      res.status(400).json({
        status: 0,
        error: error.message,
      });
    } else {
      res.status(500).json({
        status: 0,
        error: error.message,
      });
    }
  }
};

// Forgot Password

const forgot = async (req, res) => {
  try {
    // const valData = forgotSchema.parse(req.body);
    const user = await AuthService.forgotPassword(req.body);
    console.log("user==>", user);
    if (user) {
      res
        .status(250)
        .json({ status: 1, message: "Reset link send successfully" });
    }
  } catch (error) {
    if (error === "User not found") {
      res.status(400).json({
        status: 0,
        message: error,
      });
    } else {
      res.status(500).json({
        status: 0,
        message: "Internal Server Error",
      });
    }
  }
};

// Reset PAssword
const resetPassword = async (req, res) => {
  try {
    let { user_id, token } = req.query;
    const user = await AuthService.resetPassword(user_id, token, req.body);
    console.log("user==>", user);
    if (user) {
      res.status(201).json({
        status: 1,
        message: "Password updated successfully",
      });
    }
  } catch (error) {
    if (
      error.message === "No user found" ||
      error.message === "Reset Password link has expired" ||
      error.message === "Reset Password link is invalid!"
    ) {
      res.status(400).json({
        status: 0,
        error: error.message,
      });
    } else {
      res.status(500).json({
        status: 0,
        error: "Internal Server Error",
      });
    }
  }
};

// verifyMail
const verifyMail = async (req, res) => {
  const { token } = req.query;
  console.log("Token: ", token);

  try {
    const user = await AuthService.verifyMail(token);
    console.log("final res", user);
    if (user) {
      res.status(200).json({ status: 1, userInfo: user });
    } else {
      res.status(400).send("Invalid or expired token");
    }
  } catch (error) {
    console.error(error);

    res.status(500).send("Internal Server Error");
  }
};

// generate Access-token
const refreshToken = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res
      .status(400)
      .json({ status: 0, message: "Refresh token is required" });
  }
  try {
    const newAccessToken = await authService.refreshAccessToken(refreshToken);
    console.log(newAccessToken);
    return res.json({ status: 1, accessToken: newAccessToken });
  } catch (error) {
    if (error.message === "Invalid refresh token") {
      return res
        .status(401)
        .json({ status: 0, message: "Invalid refresh token" });
    }
    return res
      .status(500)
      .json({ status: 0, message: "Internal Server Error" });
  }
};

const google = async (req, res) => {
  const { credentialID, provider } = req.body;
  try {
    let google = await AuthService.google(credentialID, provider);
    res.json({
      data: google,
      status: 1,
      message: "User created successfully.",
    });
  } catch (error) {
    res.status(500).json({ status: 0, error: error.message });
  }
};
const github = async (req, res) => {
  const { credentialID, provider } = req.body;
  try {
    let github = await AuthService.github(credentialID, provider);
    res.json({
      data: github,
      status: 1,
      message: "User created successfully.",
    });
  } catch (error) {
    res.status(500).json({ status: 0, error: error.message });
  }
};
const microsoft = async (req, res) => {
  const { credentialID, provider } = req.body;
  try {
    let microsoft = await AuthService.microsoft(credentialID, provider);
    res.json({
      data: microsoft,
      status: 1,
      message: "User created successfully.",
    });
  } catch (error) {
    res.status(500).json({ status: 0, error: error.message });
  }
};

export default {
  createUser,
  forgot,
  resetPassword,
  verifyMail,
  login,
  logout,
  refreshToken,
  google,
  github,
  microsoft,
};
