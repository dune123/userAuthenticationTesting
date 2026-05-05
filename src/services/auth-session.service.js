import crypto from "node:crypto";
import { getRedisClient } from "../utils/redis-client.js";

const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_ACTIVE_SESSIONS = 5;

const hashToken = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");

const sessionKey = (sessionId) => `auth:session:${sessionId}`;
const userSessionKey = (userId) => `auth:user-sessions:${userId}`;

const createSession = async ({ userId, refreshToken, ip, userAgent }) => {
  const redis = getRedisClient();
  const sessionId = crypto.randomUUID();
  const now = Date.now();
  const refreshTokenHash = hashToken(refreshToken);

  await redis.hSet(sessionKey(sessionId), {
    userId: String(userId),
    refreshTokenHash,
    createdAt: String(now),
    lastUsedAt: String(now),
    ip: ip || "unknown",
    userAgent: userAgent || "unknown",
  });
  await redis.expire(sessionKey(sessionId), REFRESH_TOKEN_TTL_SECONDS);
  await redis.zAdd(userSessionKey(userId), [{ score: now, value: sessionId }]);

  const sessions = await redis.zRange(userSessionKey(userId), 0, -1);
  if (sessions.length > MAX_ACTIVE_SESSIONS) {
    const overflow = sessions.length - MAX_ACTIVE_SESSIONS;
    const sessionsToEvict = sessions.slice(0, overflow);
    if (sessionsToEvict.length) {
      const pipeline = redis.multi();
      for (const sid of sessionsToEvict) {
        pipeline.del(sessionKey(sid));
        pipeline.zRem(userSessionKey(userId), sid);
      }
      await pipeline.exec();
    }
  }

  return sessionId;
};

const getSession = async (sessionId) => {
  const redis = getRedisClient();
  const session = await redis.hGetAll(sessionKey(sessionId));
  if (!session || !session.userId) {
    return null;
  }
  return session;
};

const rotateSessionToken = async ({ sessionId, userId, newRefreshToken }) => {
  const redis = getRedisClient();
  const now = Date.now();

  await redis.hSet(sessionKey(sessionId), {
    refreshTokenHash: hashToken(newRefreshToken),
    lastUsedAt: String(now),
  });
  await redis.expire(sessionKey(sessionId), REFRESH_TOKEN_TTL_SECONDS);
  await redis.zAdd(userSessionKey(userId), [{ score: now, value: sessionId }]);
};

const revokeSession = async ({ userId, sessionId }) => {
  const redis = getRedisClient();
  await redis.del(sessionKey(sessionId));
  await redis.zRem(userSessionKey(userId), sessionId);
};

const revokeAllSessions = async (userId) => {
  const redis = getRedisClient();
  const sessionIds = await redis.zRange(userSessionKey(userId), 0, -1);
  if (!sessionIds.length) {
    return;
  }

  const pipeline = redis.multi();
  for (const sid of sessionIds) {
    pipeline.del(sessionKey(sid));
  }
  pipeline.del(userSessionKey(userId));
  await pipeline.exec();
};

const isRefreshTokenMatch = ({ token, session }) =>
  hashToken(token) === session.refreshTokenHash;

export {
  REFRESH_TOKEN_TTL_SECONDS,
  MAX_ACTIVE_SESSIONS,
  createSession,
  getSession,
  rotateSessionToken,
  revokeSession,
  revokeAllSessions,
  isRefreshTokenMatch,
};
