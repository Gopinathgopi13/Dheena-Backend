import bcrypt from "bcryptjs/dist/bcrypt.js";
import { prisma } from "../loaders/prisma.js";
import crypto from "crypto";
import { sendEmail, mailTemplate } from "../utils/mailHandler.js";
import passport from "passport";
import logger from "../loaders/logger.js";
import config from "../config/config.js";
import JsonWebTokenError from "jsonwebtoken";
import { generateTokens, hashedPassword } from "../utils/helpers.js";
import axios from "axios";

const jwt = JsonWebTokenError;

export const localLogin = async (data) => {
  const { email, password } = data;
  try {
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    const isPasswordValid = await bcrypt.compare(
      password,
      existingUser.password
    );

    if (!isPasswordValid) {
      throw "Your entered password is invalid.";
    }

    if (!existingUser) {
      throw "You are not an existing user.";
    }

    const userRole = await prisma.userRole.findFirst({
      where: { user_id: existingUser?.user_id },
    });

    const roleText = await prisma.role.findFirst({
      where: { role_id: userRole.role_id },
    });

    if (existingUser.is_active) {
      const userWithRelations = await prisma.user.findUnique({
        where: { user_id: existingUser.user_id },
        include: {
          addresses: true,
          schoolUser: true,
          collegeUser: true,
          professionalUser: true,
        },
      });

      const fetchUserData = await prisma.user.findUnique({
        where: { email },
        select: {
          first_name: true,
          last_name: true,
          is_active: true,
          user_id: true,
          dob: true,
          gender: true,
          interests: true,
        },
      });

      let userData = {
        ...fetchUserData,
        userType: roleText.role_name,
      };

      const { accessToken, refreshToken } = generateTokens(email);

      const allUserDetails = {
        personalDetails: userData,
        addresses: userWithRelations.addresses,
        schoolUser: userWithRelations.schoolUser,
        collegeUser: userWithRelations.collegeUser,
        professionalUser: userWithRelations.professionalUser,
        accessToken,
        refreshToken,
      };

      return allUserDetails;
    } else {
      logger.error(
        "Please activate your account. Already we have shared link to the given email id."
      );
      throw "Please activate your account. Already we have shared link to the given email id.";
    }
  } catch (error) {
    logger.error(error);
    throw error;
  }
};

export const findOrCreateUser = async (profile) => {
  console.log(profile);
  try {
    let user = await prisma.user.findUnique({
      where: { email: profile.emails[0].value },
    });

    if (!user && profile.provider === "google") {
      user = await prisma.user.create({
        data: {
          first_name: profile.name.givenName,
          last_name: profile.name.familyName,
          email: profile.emails[0].value,
          password: profile.id,
          is_active: profile._json.email_verified,
          provider_id: profile.id,
          provider: profile.provider,
        },
      });
    }

    if (!user && profile.provider === "microsoft") {
      user = await prisma.user.create({
        data: {
          first_name: profile.name.givenName,
          last_name: profile.name.familyName,
          email: profile.emails[0].value,
          password: profile.id,
          is_active: true,
          provider_id: profile.id,
          provider: profile.provider,
        },
      });
    }

    if (!user && profile.provider === "github") {
      const splitUsername = profile.displayName.split(" ");

      user = await prisma.user.create({
        data: {
          first_name: splitUsername[0],
          last_name: splitUsername[splitUsername.length - 1],
          email: profile.emails[0].value,
          password: profile.id,
          is_active: true,
          provider_id: profile.id,
          provider: profile.provider,
        },
      });
    }

    return user;
  } catch (err) {
    throw new Error(err);
  }
};

export const register = async (data) => {
  const { email, password, ...otherData } = data;
  let roleName = "user";
  const isUserMatch = await prisma.user.findUnique({
    where: {
      email: data.email,
    },
  });
  if (isUserMatch) {
    throw new Error("This email is already registered");
  }
  let role;
  if (roleName) {
    try {
      role = await prisma.role.findFirst({
        where: {
          role_name: roleName,
        },
      });
    } catch (error) {
      console.log("Error finding role:", error);
    }
  }
  const hashPassword = await hashedPassword(password);
  console.log(hashPassword);
  try {
    const user = await prisma.user.create({
      data: {
        email: email,
        password: hashPassword,
        ...otherData,
        userRoles: {
          create: {
            role_id: role.role_id,
          },
        },
      },
    });
    logger.info("User Create Successfully..!");
    const { accessToken, refreshToken } = generateTokens(email);

    // Sendind verification mail
    // const mailOption = {
    //   email: email,
    //   subject: "Account Verification",
    //   message: mailTemplate(
    //     "Click the link below to verify your email:",
    //     `http://localhost:3000/confirm-user?token=${user.user_id}`,
    //     "Verify now"
    //   ),
    // };
    // await sendEmail(mailOption);
    // return "Please check your email and activate your account.";
  } catch (error) {
    console.log(error.message);
    throw new Error(error);
  }
};

export const forgotPassword = async (data) => {
  const { email } = data;
  try {
    const user = await prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (!user) {
      throw "User not found";
    }

    const expiresAt = new Date();

    expiresAt.setHours(expiresAt.getHours() + 2);
    const token = crypto.randomBytes(20).toString("hex");
    const resetToken = crypto.createHash("sha256").update(token).digest("hex");
    const updatedUser = await prisma.user.update({
      where: { email: email },
      data: { token: resetToken, expires_at: expiresAt },
    });

    const mailOption = {
      email: updatedUser.email,
      subject: "Forgot Password Link",
      message: mailTemplate(
        "We have received a request to reset your password. Please reset your password using the link below.",
        `http://localhost:3000/reset-password?user_id=${updatedUser.user_id}&token=${resetToken}`,
        "Reset Password"
      ),
    };

    await sendEmail(mailOption);
    return updatedUser;
  } catch (error) {
    throw error;
  }
};

export const resetPassword = async (user_id, token, data) => {
  const { hashedPassword } = data;

  const userToken = await prisma.user.findUnique({
    where: {
      user_id: user_id,
    },
  });

  if (!userToken) {
    throw new Error("No user found");
  }

  const currDateTime = new Date();
  const expiresAt = new Date(userToken.expires_at);
  if (currDateTime > expiresAt) {
    throw new Error("Reset Password link has expired");
  }

  if (userToken.token !== token) {
    throw new Error("Reset Password link is invalid!");
  }

  const updatedUser = await prisma.user.update({
    where: {
      user_id: user_id,
    },
    data: {
      password: hashedPassword,
      expires_at: null,
      token: null,
    },
  });

  return updatedUser;
};

export const verifyMail = async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { user_id: req },
    });
    if (!user) {
      throw Object.assign(new Error("Not Found"), { status: 404 });
    }

    const updatedUser = await prisma.user.update({
      where: { user_id: req },
      data: { is_active: true },
    });
    return updatedUser;
  } catch (error) {
    console.error(error);
    // res.status(500).send("Internal Server Error");
    throw error;
  }
};

export const refreshAccessToken = async (refreshToken) => {
  try {
    const decoded = jwt.verify(refreshToken, config.refereshToken);

    // Find user associated with the refresh token
    const user = await prisma.user.findOne({ email: decoded.email });

    if (!user || user.refreshToken !== refreshToken) {
      throw new Error("Invalid refresh token");
    }

    // Generate a new access token
    const newAccessToken = jwt.sign(
      { email: user.email },
      config.accessTokenSecret,
      { expiresIn: "1h" }
    );

    return newAccessToken;
  } catch (error) {
    throw new Error("Invalid refresh token");
  }
};

export const google = async (credentialID, provider) => {
  try {
    const response = await axios.get(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${credentialID}`
    );
    const payload = response.data; //getting user data from response
    if (payload.aud !== config.googleClientID) {
      console.log("invalid user");
      throw "Invalid user";
      // return res.status(400).json({ error: "Invalid user" });
    }

    let role;
    let roleName = "user";
    if (roleName) {
      try {
        role = await prisma.role.findFirst({
          where: {
            role_name: roleName,
          },
        });
      } catch (error) {
        logger.error("Error finding role:", error);
        console.log("Error finding role:", error);
        throw "Error finding role";
      }
    }

    let user = await prisma.user.findUnique({
      where: { email: payload.email },
      select: {
        first_name: true,
        last_name: true,
        is_active: true,
        user_id: true,
        dob: true,
        gender: true,
        interests: true,
      },
    });

    if (!user) {
      const splitUsername = payload.name.split(" ");
      user = await prisma.user.create({
        data: {
          first_name: splitUsername[0],
          last_name: splitUsername[splitUsername.length - 1],
          email: payload.email,
          password: payload.sub,
          interests: [],
          is_active: payload.email_verified === "true" && true,
          provider_id: payload.jti,
          provider: provider,
          dob: payload.dob ? payload.dob : null,
          gender: payload.gender ? payload.gender : null,
          userRoles: {
            create: {
              role_id: role.role_id,
            },
          },
        },
        select: {
          first_name: true,
          last_name: true,
          is_active: true,
          user_id: true,
          dob: true,
          gender: true,
          interests: true,
        },
      });
    }

    const userWithRelations = await prisma.user.findUnique({
      where: { user_id: user.user_id },
      include: {
        addresses: true,
        schoolUser: true,
        collegeUser: true,
        professionalUser: true,
      },
    });

    let userData = {
      ...user,
      userType: role.role_name,
    };
    const { accessToken, refreshToken } = generateTokens(payload.email);

    const allUserDetails = {
      personalDetails: userData,
      addresses: userWithRelations.addresses,
      schoolUser: userWithRelations.schoolUser,
      collegeUser: userWithRelations.collegeUser,
      professionalUser: userWithRelations.professionalUser,
      accessToken,
      refreshToken,
    };
    // res.json({
    //   data: allUserDetails,
    //   status: 1,
    //   message: "User created successfully.",
    // });
    return allUserDetails;
  } catch (error) {
    logger.error("Invalid Google credential", error);
    throw "Invalid Google credential";
    // res.status(400).json({ error: "Invalid Google credential" });
  }
};

export const github = async (credentialID, provider) => {
  try {
    // get acces token by use this only we can fetch the user data
    const tokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      null,
      {
        params: {
          client_id: config.githubClientID,
          client_secret: config.githubClientSecret,
          code: credentialID,
        },
        headers: {
          Accept: "application/json",
        },
      }
    );

    const { access_token } = tokenResponse.data;
    if (tokenResponse.data.error) {
      return res.status(400).json({
        error: tokenResponse.data.error,
        error_description: tokenResponse.data.error_description,
      });
    }

    // Get user info
    const userResponse = await axios.get("https://api.github.com/user", {
      headers: {
        Authorization: `token ${access_token}`,
      },
    });
    const userDetails = userResponse.data;

    // If there is no email in user info we want to fetch by using below format. we can get all datas [ex: our primary email, secondary email]
    let getEmail;
    if (!userResponse.data.email) {
      console.log("accessed");
      const emailsResponse = await axios.get(
        "https://api.github.com/user/emails",
        {
          headers: {
            Authorization: `token ${access_token}`,
          },
        }
      );
      const { email } = emailsResponse.data.find(
        (emailObj) => emailObj.email && emailObj.primary
      );
      getEmail = email;
    }

    let role;
    let roleName = "user";
    if (roleName) {
      try {
        role = await prisma.role.findFirst({
          where: {
            role_name: roleName,
          },
        });
      } catch (error) {
        logger.error("Error finding role:", error);
        throw "Error finding role";
      }
    }

    let user = await prisma.user.findUnique({
      where: { email: getEmail || userDetails.email },
      select: {
        first_name: true,
        last_name: true,
        is_active: true,
        user_id: true,
        dob: true,
        gender: true,
        interests: true,
      },
    });
    if (!user) {
      const splitUsername = userDetails.name.split(" ");
      user = await prisma.user.create({
        data: {
          first_name: splitUsername[0],
          last_name: splitUsername[splitUsername.length - 1],
          email: userDetails.email || getEmail,
          password: userDetails.id.toString(),
          is_active: true,
          interests: [],
          provider_id: userDetails.id.toString(),
          provider: provider,
          dob: userDetails.dob ? userDetails.dob : null,
          gender: userDetails.gender ? userDetails.gender : null,
          userRoles: {
            create: {
              role_id: role.role_id,
            },
          },
        },
        select: {
          first_name: true,
          last_name: true,
          is_active: true,
          user_id: true,
          dob: true,
          gender: true,
          interests: true,
        },
      });
    }

    // User details
    let userData = {
      ...user,
      userType: role.role_name,
    };

    const userWithRelations = await prisma.user.findUnique({
      where: { user_id: user.user_id },
      include: {
        addresses: true,
        schoolUser: true,
        collegeUser: true,
        professionalUser: true,
      },
    });

    // Combine the selected fields and the included relations

    const { accessToken, refreshToken } = generateTokens(
      userDetails.email || getEmail
    );
    const allUserDetails = {
      personalDetails: userData,
      addresses: userWithRelations.addresses,
      schoolUser: userWithRelations.schoolUser,
      collegeUser: userWithRelations.collegeUser,
      professionalUser: userWithRelations.professionalUser,
      accessToken,
      refreshToken,
    };

    return allUserDetails;
  } catch (error) {
    logger.error("Invalid Github credential", error);
    throw "Invalid Github credential";
  }
};

export const microsoft = async (credentialID, provider) => {
  try {
    const decodeToken = jwt.decode(credentialID);

    let user = await prisma.user.findUnique({
      where: { email: decodeToken.email },
      select: {
        first_name: true,
        last_name: true,
        is_active: true,
        user_id: true,
        dob: true,
        gender: true,
        interests: true,
      },
    });

    let role;
    let roleName = "user";
    if (roleName) {
      try {
        role = await prisma.role.findFirst({
          where: {
            role_name: roleName,
          },
        });
      } catch (error) {
        logger.error("Error finding role:", error);
        throw "Error finding role";
      }
    }

    if (!user) {
      const splitUsername = decodeToken.name.split(" ");
      user = await prisma.user.create({
        data: {
          first_name: splitUsername[0],
          last_name: splitUsername[splitUsername.length - 1],
          email: decodeToken.email,
          password: decodeToken.aud,
          is_active: true,
          interests: [],
          provider_id: decodeToken.nonce,
          provider: provider,
          dob: decodeToken.dob ? decodeToken.dob : null,
          gender: decodeToken.gender ? decodeToken.gender : null,
          userRoles: {
            create: {
              role_id: role.role_id,
            },
          },
        },
        select: {
          first_name: true,
          last_name: true,
          is_active: true,
          user_id: true,
          dob: true,
          gender: true,
          interests: true,
        },
      });
    }

    let userData = {
      ...user,
      userType: role.role_name,
    };

    const userWithRelations = await prisma.user.findUnique({
      where: { user_id: user.user_id },
      include: {
        addresses: true,
        schoolUser: true,
        collegeUser: true,
        professionalUser: true,
      },
    });

    const { accessToken, refreshToken } = generateTokens(decodeToken.email);

    const allUserDetails = {
      personalDetails: { ...userData },
      addresses: userWithRelations.addresses,
      schoolUser: userWithRelations.schoolUser,
      collegeUser: userWithRelations.collegeUser,
      professionalUser: userWithRelations.professionalUser,
      accessToken,
      refreshToken,
    };
    return allUserDetails;
  } catch (error) {
    logger.error("Microsoft OAuth failed", error);
    throw "Microsoft OAuth failed";
  }
};
