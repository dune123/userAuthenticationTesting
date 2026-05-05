import { AuthEvent } from "../models/auth-event.model.js";

const getRequestIp = (req) => req.ip || req.headers["x-forwarded-for"] || "unknown";

const logAuthEvent = async ({
  req,
  eventType,
  success,
  userId = null,
  email = null,
  reason = null,
  metadata = {},
}) => {
  try {
    await AuthEvent.create({
      eventType,
      success,
      userId,
      email,
      ip: getRequestIp(req),
      userAgent: req.headers["user-agent"] || "unknown",
      reason,
      metadata,
    });
  } catch (error) {
    console.error("Failed to persist auth event:", error);
  }
};

export { logAuthEvent };
