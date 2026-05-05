import { ApiError } from "../utils/api-error.js";
import { getRedisClient } from "../utils/redis-client.js";

const LOGIN_WINDOW_SECONDS = 15 * 60;
const LOGIN_MAX_FAILS_PER_IP = 5;

const AUTH_IP_WINDOW_SECONDS = 15 * 60;
const AUTH_IP_MAX_REQUESTS = 120;

const AUTH_USER_WINDOW_SECONDS = 15 * 60;
const AUTH_USER_MAX_REQUESTS = 180;

const clientIp = (req) => req.ip || req.headers["x-forwarded-for"] || "unknown";

const incrementCounter = async (key, windowSeconds) => {
  const redis = getRedisClient();
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, windowSeconds);
  }
  const ttl = await redis.ttl(key);
  return { count, ttl };
};

const checkLoginBlocked = async (req, _res, next) => {
  const ip = clientIp(req);
  const redis = getRedisClient();
  const key = `auth:login-fail:ip:${ip}`;
  const failures = Number((await redis.get(key)) || 0);

  if (failures >= LOGIN_MAX_FAILS_PER_IP) {
    const ttl = await redis.ttl(key);
    throw new ApiError(
      429,
      `Too many failed login attempts. Try again in ${Math.max(ttl, 1)} seconds`,
    );
  }
  next();
};

const recordLoginFailure = async (req) => {
  const ip = clientIp(req);
  const key = `auth:login-fail:ip:${ip}`;
  await incrementCounter(key, LOGIN_WINDOW_SECONDS);
};

const clearLoginFailures = async (req) => {
  const ip = clientIp(req);
  const redis = getRedisClient();
  await redis.del(`auth:login-fail:ip:${ip}`);
};

const rateLimitByIp = async (req, _res, next) => {
  const ip = clientIp(req);
  const key = `auth:req:ip:${ip}`;
  const { count, ttl } = await incrementCounter(key, AUTH_IP_WINDOW_SECONDS);

  if (count > AUTH_IP_MAX_REQUESTS) {
    throw new ApiError(
      429,
      `Too many requests from this IP. Retry in ${Math.max(ttl, 1)} seconds`,
    );
  }
  next();
};

const rateLimitByUser = async (req, _res, next) => {
  if (!req.user?._id) {
    return next();
  }
  const key = `auth:req:user:${req.user._id}`;
  const { count, ttl } = await incrementCounter(key, AUTH_USER_WINDOW_SECONDS);

  if (count > AUTH_USER_MAX_REQUESTS) {
    throw new ApiError(
      429,
      `Too many requests for this user. Retry in ${Math.max(ttl, 1)} seconds`,
    );
  }
  next();
};

export {
  checkLoginBlocked,
  recordLoginFailure,
  clearLoginFailures,
  rateLimitByIp,
  rateLimitByUser,
};
