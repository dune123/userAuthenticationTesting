import { createClient } from "redis";

let redisClient;

const getRedisClient = () => {
  if (!redisClient) {
    redisClient = createClient({
      url: process.env.REDIS_URL || "redis://127.0.0.1:6379",
    });

    redisClient.on("error", (error) => {
      console.error("Redis client error:", error);
    });
  }

  return redisClient;
};

const connectRedis = async () => {
  const client = getRedisClient();
  if (!client.isOpen) {
    await client.connect();
    console.log("✅ Redis connected");
  }
  return client;
};

export { getRedisClient, connectRedis };
