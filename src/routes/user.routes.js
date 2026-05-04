import {Router} from "express"
import { login, logout, registerUser } from "../controllers/user.controller.js";
import { verifyJWT } from "../middleware/auth.middleware.js";

const router = Router();

// unsecured route
router.post("/register",registerUser)
router.post("/login",login)
router.post("/logout",verifyJWT,logout)

export default router