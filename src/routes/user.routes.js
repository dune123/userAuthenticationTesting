import { Router } from "express";
import {
  getLoggedInUser,
  login,
  logout,
  refreshAccessToken,
  registerUser,
} from "../controllers/user.controller.js";
import { verifyJWT } from "../middleware/auth.middleware.js";
import { validate } from "../middleware/validator.middleware.js";
import { userLoginValidator, userRegisterValidator } from "../validator/index.js";

const router = Router();

// unsecured route
router.post("/register", userRegisterValidator(), validate, registerUser);
router.post("/login", userLoginValidator(), validate, login);
router.post("/refresh-token", refreshAccessToken);
router.post("/logout", verifyJWT, logout);
router.get("/me", verifyJWT, getLoggedInUser);

export default router