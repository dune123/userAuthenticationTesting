import { Router } from "express";
import {
  getLoggedInUser,
  login,
  logout,
  logoutAllDevices,
  refreshAccessToken,
  registerUser,
} from "../controllers/user.controller.js";
import { verifyJWT } from "../middleware/auth.middleware.js";
import {
  checkLoginBlocked,
  rateLimitByIp,
  rateLimitByUser,
} from "../middleware/auth-rate-limit.middleware.js";
import { validate } from "../middleware/validator.middleware.js";
import { userLoginValidator, userRegisterValidator } from "../validator/index.js";

const router = Router();

// unsecured route
router.post("/register", rateLimitByIp, userRegisterValidator(), validate, registerUser);
router.post("/login", rateLimitByIp, checkLoginBlocked, userLoginValidator(), validate, login);
router.post("/refresh-token", rateLimitByIp, refreshAccessToken);
router.post("/logout", rateLimitByIp, verifyJWT, rateLimitByUser, logout);
router.post("/logout-all", rateLimitByIp, verifyJWT, rateLimitByUser, logoutAllDevices);
router.get("/me", rateLimitByIp, verifyJWT, rateLimitByUser, getLoggedInUser);

export default router