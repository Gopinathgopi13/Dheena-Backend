import JsonWebTokenError from "jsonwebtoken";
import config from "../config/config.js";
import bcrypt from "bcryptjs/dist/bcrypt.js";
import logger from "../loaders/logger.js";

const jwt = JsonWebTokenError;
export const generateTokens = (email) => {
  const accessToken = jwt.sign({ email: email }, config.accessToken, {
    expiresIn: "14m",
  });
  const refreshToken = jwt.sign({ email: email }, config.refereshToken, {
    expiresIn: "30d",
  });

  return { accessToken, refreshToken };
};

export const hashedPassword = async (password) => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (error) {
    logger.error(error.message);
  }
};

export const convertToTimeStamp = (data) => {
  return new Date(data).toISOString();
};
