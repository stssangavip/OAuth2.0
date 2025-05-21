import redis from '../config/redisConfig';

export interface RedisServiceStatus {
  service: string;
  status: string;
  error: string | null;
}

const redisUtility = {

  async getRedisData(redisKey: string): Promise<string | null> {
    const value = await redis.get(redisKey);
    return value ? JSON.parse(value).toString() : null;
  },

async setRedisDataWithExpiry<T>(redisKey: string, value: T, expiryInSeconds: number): Promise<void> {
  const jsonData = JSON.stringify(value);
  await redis.set(redisKey, jsonData, 'EX', expiryInSeconds); // 'EX' sets expiry in seconds
}
,

  async deleteRedisData(redisKey: string): Promise<void> {
    await redis.del(redisKey);
  },

  async getRedisJson<T = any>(redisKey: string): Promise<T | null> {
    const data = await redis.get(redisKey);
    return data ? JSON.parse(data) : null;
  },

  async checkRedis(): Promise<RedisServiceStatus> {
    try {
      const res = await redis.ping();
      return {
        service: 'Redis',
        status: res === 'PONG' ? 'UP' : 'DOWN',
        error: null,
      };
    } catch (err: any) {
      return {
        service: 'Redis',
        status: 'DOWN',
        error: err.message || 'Unknown error',
      };
    }
  },
};

export default redisUtility;
