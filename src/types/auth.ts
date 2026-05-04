import { JwtPayload } from 'jsonwebtoken';

export type RiskLevel = 'low' | 'normal' | 'medium' | 'high';

export interface AuthContext extends JwtPayload {
  sub: string;
  jti: string;
  sid?: string;
  client_id?: string;
  azp?: string;
  scope?: string;
  device_id?: string;
  roles?: string[];
  aal?: number;
  amr?: string[];
  risk_level?: RiskLevel;
  token_use?: string;
}

export interface OAuthClientConfig {
  clientId: string;
  clientName: string;
  clientType: string;
  status: string;
  redirectUris: string[];
  allowedScopes: string[];
  allowedGrantTypes: string[];
  tokenEndpointAuthMethod: string;
  clientSecretHash?: string | null;
  pkceRequired: boolean;
}

export interface TokenSet {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope: string;
}

export interface DeviceInfo {
  device_id?: string;
  deviceId?: string;
  device_name?: string;
  deviceName?: string;
  platform?: string;
  app_version?: string;
  appVersion?: string;
  os_version?: string;
  osVersion?: string;
  public_signing_key?: string;
  publicSigningKey?: string;
  key_algorithm?: string;
  keyAlgorithm?: string;
  push_token_hash?: string;
  pushTokenHash?: string;
}
