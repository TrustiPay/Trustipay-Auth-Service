import { Request } from 'express';
import { prisma } from '../db/prisma';
import { hashSensitive } from './crypto';
import { newId } from './ids';
import { incrementMetric } from './metrics';

interface AuditInput {
  eventType: string;
  result: 'success' | 'failure' | 'blocked' | 'info';
  req?: Request;
  userId?: string | null;
  sessionId?: string | null;
  deviceId?: string | null;
  clientId?: string | null;
  riskLevel?: string | null;
  metadata?: Record<string, unknown>;
}

function ipFromRequest(req?: Request): string | null {
  if (!req) return null;
  return req.header('x-forwarded-for')?.split(',')[0]?.trim() || req.ip || req.socket.remoteAddress || null;
}

export async function audit(input: AuditInput): Promise<void> {
  incrementMetric(`auth_audit_${input.result}_total`);
  try {
    await prisma.auditEvent.create({
      data: {
        eventId: newId('evt'),
        eventType: input.eventType,
        result: input.result,
        userId: input.userId || null,
        sessionId: input.sessionId || null,
        deviceId: input.deviceId || null,
        clientId: input.clientId || null,
        requestId: input.req?.requestId || null,
        ipHash: hashSensitive(ipFromRequest(input.req)),
        userAgentHash: hashSensitive(input.req?.header('user-agent')),
        riskLevel: input.riskLevel || null,
        metadataJson: input.metadata ? JSON.stringify(input.metadata) : null,
      },
    });
  } catch (error) {
    console.error({ message: 'failed to write audit event', error });
  }
}
