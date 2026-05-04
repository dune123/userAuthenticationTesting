import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import connectDB from "./db/index.js";
import cookieParser from "cookie-parser";
//import routes
import healthCheckRouter from "./routes/health.routes.js";
import userRouter from "./routes/user.routes.js"

dotenv.config({
  path: ".env",
});
const app = express();
// basic configurations
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());

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
app.use("/api/v1/auth",userRouter)

const PORT = process.env.PORT || 5000;

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log("app is listening on port 3000");
  });
}).catch(((err)=>{
    console.error("MongoDB connection error", err);
    process.exit(1);
}))
