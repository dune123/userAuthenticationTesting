import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import connectDB from "./db/index.js";
import cookieParser from "cookie-parser";
import { ApiError } from "./utils/api-error.js";
import rateLimit from "express-rate-limit"
//import routes
import healthCheckRouter from "./routes/health.routes.js";
import userRouter from "./routes/user.routes.js";

dotenv.config({
  path: ".env",
});
const app = express();
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
});


// basic configurations
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());
app.use(limiter);

// cors configurations
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://locahost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

//routes
app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/auth", userRouter);

app.use((err, req, res, next) => {
  const statusCode = err?.statusCode || 500;
  const message = err?.message || "Internal Server Error";

  if (!(err instanceof ApiError) && statusCode >= 500) {
    console.error("Unhandled error:", err);
  }

  return res.status(statusCode).json({
    success: false,
    statusCode,
    message,
    errors: err?.errors || [],
  });
});

const PORT = process.env.PORT || 5000;

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log("app is listening on port 3000");
  });
}).catch(((err) => {
    console.error("MongoDB connection error", err);
    process.exit(1);
}));
