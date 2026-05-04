import { start } from './server';

start().catch((error) => {
  console.error(error);
  process.exit(1);
});

/*
import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';

dotenv.config();

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

// Routes
app.get('/', (req: Request, res: Response) => {
  res.send('Hello World!');
});

// Auth Routes
app.post('/auth/register/start', async (req: Request, res: Response): Promise<any> => {
  try {
    const { email, phone, password, device_info } = req.body;

    const existing = await prisma.user.findFirst({
      where: { OR: [{ email: email || '' }, { phone: phone || '' }] }
    });

    if (existing) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const passwordHash = await argon2.hash(password);
    const user = await prisma.user.create({
      data: {
        email,
        phone,
        passwordHash,
        status: 'ACTIVE',
      }
    });

    return res.status(201).json({ success: true, userId: user.id });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/auth/legacy/mobile-login', async (req: Request, res: Response): Promise<any> => {
  try {
    const { email, phone, password, client_id, device_info } = req.body;

    const user = await prisma.user.findFirst({
      where: { OR: [{ email: email || '' }, { phone: phone || '' }] }
    });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await argon2.verify(user.passwordHash, password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    let deviceId = device_info?.device_id || `dev_${uuidv4().substring(0, 8)}`;

    const device = await prisma.device.upsert({
      where: { deviceId },
      update: {
        platform: device_info?.platform,
        appVersion: device_info?.app_version,
      },
      create: {
        userId: user.id,
        deviceId,
        platform: device_info?.platform,
        appVersion: device_info?.app_version,
      }
    });

    const refreshToken = crypto.randomBytes(32).toString('hex');
    const refreshTokenHash = await argon2.hash(refreshToken);

    const session = await prisma.session.create({
      data: {
        userId: user.id,
        deviceId: device.id,
        refreshTokenHash,
        validUntil: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      }
    });

    const payload = {
      sub: user.id,
      aud: 'trustipay-api',
      iss: 'https://api.trustipay.example/auth',
      jti: `atk_${uuidv4()}`,
      sid: session.id,
      azp: client_id || 'trustipay-android',
      device_id: device.deviceId,
      scope: 'openid profile wallet:read wallet:transfer offline:sync offline:tokens:request',
      roles: ['user'],
      risk_level: 'normal',
    };

    let privateKeyPEM = process.env.JWT_PRIVATE_KEY;
    if (!privateKeyPEM) {
      const privateKeyPath = process.env.JWT_PRIVATE_KEY_PATH || './keys/private.pem';
      if (fs.existsSync(privateKeyPath)) {
        privateKeyPEM = fs.readFileSync(privateKeyPath, 'utf8');
      } else {
        // Fallback for missing keys
        privateKeyPEM = crypto.generateKeyPairSync('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        }).privateKey;
      }
    } else {
      privateKeyPEM = privateKeyPEM.replace(/\\n/g, '\n');
    }

    const accessToken = jwt.sign(payload, privateKeyPEM, { algorithm: 'RS256' });

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: refreshToken,
      scope: payload.scope
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Keys Route
app.get('/.well-known/jwks.json', (req: Request, res: Response) => {
  let publicKeyPEM = process.env.JWT_PUBLIC_KEY;
  if (!publicKeyPEM) {
    const publicKeyPath = process.env.JWT_PUBLIC_KEY_PATH || './keys/public.pem';
    if (fs.existsSync(publicKeyPath)) {
      publicKeyPEM = fs.readFileSync(publicKeyPath, 'utf8');
    } else {
      return res.status(404).json({ message: 'Public key not found' });
    }
  } else {
    publicKeyPEM = publicKeyPEM.replace(/\\n/g, '\n');
  }

  const keyObj = crypto.createPublicKey(publicKeyPEM);
  const jwk = keyObj.export({ format: 'jwk' }) as any;

  return res.json({
    keys: [
      {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        alg: 'RS256',
        kid: 'key-1',
        use: 'sig',
      },
    ],
  });
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Express server listening on port ${port}`);
});
*/
