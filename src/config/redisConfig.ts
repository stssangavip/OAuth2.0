import Redis from 'ioredis';

// Load environment variables safely
const redisHost = process.env.RedisHost || 'localhost';
const redisPort = Number(process.env.RedisPort) || 6379;
const redisPassword = process.env.RedisPassword || '';

const redisConnection = new Redis({
  host: redisHost,
  port: redisPort,
  password: redisPassword,
});

export default redisConnection;
