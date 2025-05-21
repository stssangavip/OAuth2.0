import { Request, Response } from 'express';
import { decryptAES, generateAccessToken, generateRefreshToken, encrypt, verifyRefreshToken } from '../Utilities/Utility';
import redisUtility from '../Utilities/redisUtility';
import jwt from 'jsonwebtoken';

export const generateTokens = async (req: Request, res: Response) => {
    console.log('👉 Incoming /oauth/token request body:', req.body);
  try {
    const { clientId, userToken, clientSecret, refreshToken } = req.body;

    if (refreshToken) {
      const { decoded, expired } = verifyRefreshToken(refreshToken);

      if (!decoded) {
        return res.status(401).json({ message: 'Invalid refresh token' });
      }
      if (expired) {
        return res.status(401).json({ message: 'Expired refresh token' });
      }
      const sub = Array.isArray(decoded.sub) ? decoded.sub[0] : decoded.sub || '';
      const aud = Array.isArray(decoded.aud) ? decoded.aud[0] : decoded.aud || '';
      const redisData = await redisUtility.getRedisJson(sub);

      if (!redisData || redisData.refreshToken !== refreshToken) {
        return res.status(401).json({ message: 'Invalid refresh token' });
      }

      const accessToken = generateAccessToken(sub, aud, '');

      const tokenData = {
        accessToken,
        refreshToken,
        userToken: aud
      };

      // Calculate Redis expiry based on token expiration
      const currentUnixTime = Math.floor(Date.now() / 1000);
      let expiryInSeconds = 60 * 60 * 24 * 30; // default 30 days

      if (typeof decoded.exp === 'number') {
        expiryInSeconds = decoded.exp - currentUnixTime;
      }

      await redisUtility.setRedisDataWithExpiry(sub, tokenData, expiryInSeconds);

      return res.status(200).json({
        access_token: accessToken,
        refresh_token: refreshToken
      });
    }

 
    if (!clientId || !userToken || !clientSecret) {
      return res.status(400).json({ error: 'Missing encrypted credentials' });
    }

    const encryptedValue = encrypt(clientId, userToken, clientSecret);
    const decryptedValue = decryptAES(encryptedValue, clientSecret);
    const { clientId: decryptedClientId, userToken: decryptedUserToken } = JSON.parse(decryptedValue);

    const accessToken = generateAccessToken(decryptedClientId, decryptedUserToken, clientSecret);
    const newRefreshToken = generateRefreshToken(decryptedClientId, decryptedUserToken, clientSecret);

    const tokenData = {
      accessToken,
      refreshToken: newRefreshToken,
      userToken: decryptedUserToken
    };

    await redisUtility.setRedisDataWithExpiry(decryptedClientId, tokenData, 60 * 60 * 24 * 30); 

    return res.status(200).json({
      access_token: accessToken,
      refresh_token: newRefreshToken
    });

  } catch (error) {
    console.error('OAuth error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

export const accessverifed = async (req: Request, res: Response) => {
    console.log('👉 Incoming /oauth/accessverifed request body:', req.body);
  const { client_id, redirect_uri,  response_type, state } = req.query;

  // Simulate login and grant flow (normally you'd show a login UI)
  if (response_type !== 'code') {
    return res.status(400).send('Unsupported response_type');
  }

  const authCode = 'test_auth_code'; // Generate this per-user in real apps

  // Redirect Zapier back with the auth code
  return res.redirect(`${redirect_uri}?code=${authCode}&state=${state}`);
}


export const VerifedAuthentication = async (req: Request, res: Response) =>  {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // fake response, normally you'd verify the token
  res.status(200).json({ user: 'test-user' });
};
// Example: POST /register-webhook
export const RegisterWebHook = async (req: Request, res: Response) => {
 
      console.log('Incoming /oauth/RegisterWebHook request body:', req.body);
      console.log('Incoming /oauth/RegisterWebHook request body:', req.headers.authorization);
       const { userId, webhookUrl } = req.body;
  const authHeader = req.headers.authorization;

  const token = authHeader?.split(' ')[1];

  const decoded = verifyCrtAccessToken(token || '');
  if (!decoded) {
    return res.status(401).json({ message: 'Invalid access token' });
  }
const tokenData = {
      webhookUrl: webhookUrl,
      userId: userId
    };
  await redisUtility.setRedisDataWithExpiry(decoded.clientId, tokenData, 60 * 60 * 24 * 30);

  res.status(200).json({ message: 'Webhook registered' });
};

export const verifyCrtAccessToken = (token: string): { clientId: string; clientSecret?: string; userToken: string } | null => {
  try {
    const MASTER_SECRET = process.env.MASTER_SECRET_KEY ||'';
    const decoded = jwt.verify(token, MASTER_SECRET) as jwt.JwtPayload;

    const clientId = decoded.sub as string;
    const userToken = decoded.aud as string;
    const clientSecret = decoded.clientSecret as string; // Optional, if you included it during token generation

    if (!clientId || !userToken) {
      throw new Error('Invalid token payload');
    }

    return {
      clientId,
      userToken,
      clientSecret
    };
  } catch (error) {
    console.error('Access token verification failed:', error);
    return null;
  }
};