import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import jwt from "jsonwebtoken";
import {
  createSession,
  getSession,
  isRefreshTokenMatch,
  revokeAllSessions,
  revokeSession,
  rotateSessionToken,
} from "../services/auth-session.service.js";
import { clearLoginFailures, recordLoginFailure } from "../middleware/auth-rate-limit.middleware.js";
import { logAuthEvent } from "../utils/auth-event-logger.js";

const cookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
};

const generateAccessAndRefreshTokens = async ({ userId, sessionId }) => {
  const user = await User.findById(userId).select("-password");
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  if (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
    throw new ApiError(
      500,
      "JWT is not configured. Set ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET in your .env file.",
    );
  }

  try {
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken(sessionId);
    return { accessToken, refreshToken };
  } catch (error) {
    console.error("generateAccessAndRefreshTokens:", error);
    throw new ApiError(
      500,
      error?.message || "Something went wrong while generating access token",
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new ApiError(400, "All fields are required");
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new ApiError(409, "User with this email already exists", []);
  }

  const user = await User.create({ email, password });
  const createdUser = await User.findById(user._id).select("-password -refreshToken");
  await logAuthEvent({
    req,
    eventType: "register",
    success: true,
    userId: user._id,
    email,
  });

  return res.status(201).json(
    new ApiResponse(
      200,
      { user: createdUser },
      "User registered successfully and verification email has been sent on your email",
    ),
  );
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    throw new ApiError(400, " email is required");
  }

  const user = await User.findOne({ email: email });

  if (!user) {
    await recordLoginFailure(req);
    await logAuthEvent({
      req,
      eventType: "login",
      success: false,
      email,
      reason: "user_not_found",
    });
    throw new ApiError(400, "User does not exists");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    await recordLoginFailure(req);
    await logAuthEvent({
      req,
      eventType: "login",
      success: false,
      userId: user._id,
      email,
      reason: "invalid_password",
    });
    throw new ApiError(400, "Invalid credentials");
  }

  await clearLoginFailures(req);
  const sessionId = await createSession({
    userId: user._id,
    refreshToken: "temp",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens({
    userId: user._id,
    sessionId,
  });
  await rotateSessionToken({ sessionId, userId: user._id, newRefreshToken: refreshToken });

  const loggedInUser = await User.findById(user._id);
  await logAuthEvent({
    req,
    eventType: "login",
    success: true,
    userId: user._id,
    email,
    metadata: { sessionId },
  });

  return res
    .status(200)
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", refreshToken, cookieOptions)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in successfully",
      ),
    );
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Refresh token is required");
  }

  if (!process.env.REFRESH_TOKEN_SECRET) {
    throw new ApiError(500, "Refresh token secret is not configured");
  }

  let decodedToken;
  try {
    decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
  } catch (error) {
    await logAuthEvent({
      req,
      eventType: "refresh_token",
      success: false,
      reason: "invalid_or_expired_refresh_token",
    });
    throw new ApiError(401, "Invalid or expired refresh token");
  }

  const user = await User.findById(decodedToken?._id);
  if (!user) {
    throw new ApiError(401, "Invalid refresh token");
  }

  const sessionId = decodedToken?.sid;
  if (!sessionId) {
    throw new ApiError(401, "Malformed refresh token");
  }

  const session = await getSession(sessionId);
  if (!session || String(session.userId) !== String(user._id)) {
    await logAuthEvent({
      req,
      eventType: "refresh_token",
      success: false,
      userId: user._id,
      reason: "session_not_found",
      metadata: { sessionId },
    });
    throw new ApiError(401, "Session does not exist. Please login again");
  }

  if (!isRefreshTokenMatch({ token: incomingRefreshToken, session })) {
    await revokeAllSessions(user._id);
    await logAuthEvent({
      req,
      eventType: "refresh_token",
      success: false,
      userId: user._id,
      reason: "refresh_token_reuse_detected",
      metadata: { sessionId },
    });
    throw new ApiError(401, "Refresh token is expired or already used");
  }

  const { accessToken, refreshToken: newRefreshToken } = await generateAccessAndRefreshTokens({
    userId: user._id,
    sessionId,
  });
  await rotateSessionToken({ sessionId, userId: user._id, newRefreshToken: newRefreshToken });
  await logAuthEvent({
    req,
    eventType: "refresh_token",
    success: true,
    userId: user._id,
    metadata: { sessionId },
  });

  return res
    .status(200)
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", newRefreshToken, cookieOptions)
    .json(
      new ApiResponse(
        200,
        { accessToken, refreshToken: newRefreshToken },
        "Access token refreshed successfully",
      ),
    );
});

const logout = asyncHandler(async (req, res) => {
  const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
  if (incomingRefreshToken && process.env.REFRESH_TOKEN_SECRET) {
    try {
      const decoded = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
      if (decoded?.sid) {
        await revokeSession({ userId: req.user._id, sessionId: decoded.sid });
      }
    } catch (error) {
      // Intentionally ignore token parse errors during logout.
    }
  }

  await logAuthEvent({
    req,
    eventType: "logout_single",
    success: true,
    userId: req.user._id,
  });

  return res
    .status(200)
    .clearCookie("accessToken", cookieOptions)
    .clearCookie("refreshToken", cookieOptions)
    .json(new ApiResponse(200, {}, "User logged out"));
});

const logoutAllDevices = asyncHandler(async (req, res) => {
  await revokeAllSessions(req.user._id);
  await logAuthEvent({
    req,
    eventType: "logout_all",
    success: true,
    userId: req.user._id,
  });

  return res
    .status(200)
    .clearCookie("accessToken", cookieOptions)
    .clearCookie("refreshToken", cookieOptions)
    .json(new ApiResponse(200, {}, "User logged out from all devices"));
});

const getLoggedInUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).select("-password -refreshToken");
  await logAuthEvent({
    req,
    eventType: "me_access",
    success: true,
    userId: req.user._id,
  });
  return res
    .status(200)
    .json(new ApiResponse(200, { user }, "Logged in user fetched successfully"));
});

export { registerUser, login, refreshAccessToken, logout, logoutAllDevices, getLoggedInUser };
