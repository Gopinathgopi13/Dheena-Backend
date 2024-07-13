import dotenv from "dotenv";

const envFound = dotenv.config();

if (envFound.error) {
  throw new Error(".env file not found..!");
}

process.env.PORT = process.env.PORT || 8000;
export default {
  port: parseInt(process.PORT) || 8000,
  sessionSecret: process.env.SESSION_SECRET,
  email: process.env.EMAIL_ID,
  pass: process.env.EMAIL_PASSWORD,
  jwtSecret: process.env.JWT_SECRET,
  accessToken: process.env.ACCESS_TOKEN,
  refereshToken: process.env.REFERESH_TOKEN,
  // linkedin
  linkedinClientID: process.env.LINKEDIN_CLIENT_ID,
  linkedinClientSecret: process.env.LINKEDIN_CLIENT_SECRET,
  linkedinCallBackURL: process.env.LINKEDIN_CALLBACK_URL,

  // Google
  googleClientID: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
  googleCallBackURL: process.env.GOOGLE_CALLBACK_URL,

  // microsoft
  microsoftClientID: process.env.MICROSOFT_CLIENT_ID,
  microsoftClientSecret: process.env.MICROSOFT_CLIENT_SECRET,
  microsoftCallBackURL: process.env.MICROSOFT_CALLBACK_URL,

  // github
  githubClientID: process.env.GITHUB_CLIENT_ID,
  githubClientSecret: process.env.GITHUB_CLIENT_SECRET,
  githubCallBackURL: process.env.GITHUB_CALLBACK_URL,
};
