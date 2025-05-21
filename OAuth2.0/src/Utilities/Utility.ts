import crypto from 'crypto';
import jwt from 'jsonwebtoken';


const IV_LENGTH = 16;

export function decryptAES(cipherText: string, clientSecret: string): string {
  const [ivHex, encryptedData] = cipherText.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const key = crypto.createHash('sha256').update(clientSecret).digest(); // FIXED

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}


const MASTER_SECRET = process.env.MASTER_SECRET_KEY;

function getUnixEpoch(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}


export function generateAccessToken(
  clientId: string,
  userToken: string,
  clientSecret: string
): string {
  const now = new Date();
  const issuedAt = getUnixEpoch(now);
  const expiresAt = getUnixEpoch(new Date(now.getTime() + 60 * 60 * 1000)); // 1 hour later


  const payload = {
    iss: `https://v1-tbs-oauth.stssprint.com/v2/`,
    sub: clientId,
    aud: userToken,
    userUniqueId: '',
    iat: issuedAt,
    exp: expiresAt,
  };

  const token = jwt.sign(payload, MASTER_SECRET, { algorithm: 'HS256' });

  return token;
}

export function generateRefreshToken(
  clientId: string,
  userToken: string,
  clientSecret: string
): string {
  const now = new Date();
  const issuedAt = getUnixEpoch(now);
  const expiresAt = getUnixEpoch(new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)); // 30 days later

  const payload = {
    iss: `https://v1-tbs-oauth.stssprint.com/v2/`,
    sub: clientId,
    aud: userToken,
    userUniqueId: '',
    iat: issuedAt,
    exp: expiresAt,
  };

  const token = jwt.sign(payload, MASTER_SECRET, { algorithm: 'HS256' });

  return token;
}

const algorithm = 'aes-256-cbc';
const iv = crypto.randomBytes(16);

export function encrypt(clientId: string, userToken: string, clientSecret: string): string {
  // Derive a 256-bit key from clientSecret using SHA-256
  const key = crypto.createHash('sha256').update(clientSecret).digest();
  const iv = crypto.randomBytes(16);

  const dataToEncrypt = JSON.stringify({ clientId, userToken });

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(dataToEncrypt, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Format: iv:encryptedData (both hex)
  return `${iv.toString('hex')}:${encrypted}`;
}

export function verifyRefreshToken(token: string): { decoded: jwt.JwtPayload | null; expired: boolean } {
  try {''
    const decoded = jwt.verify(token, MASTER_SECRET) as jwt.JwtPayload;
    return { decoded, expired: false };
  } catch (error: any) {
    if (error.name === 'TokenExpiredError') {
      const decoded = jwt.decode(token) as jwt.JwtPayload;
      return { decoded, expired: true };
    }
    return { decoded: null, expired: false };
  }
}
