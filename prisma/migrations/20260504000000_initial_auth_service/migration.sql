PRAGMA foreign_keys=OFF;

CREATE TABLE "users" (
  "user_id" TEXT NOT NULL PRIMARY KEY,
  "status" TEXT NOT NULL,
  "display_name" TEXT,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" DATETIME NOT NULL,
  "locked_at" DATETIME,
  "lock_reason" TEXT,
  "deleted_at" DATETIME
);

CREATE TABLE "user_emails" (
  "email_id" TEXT NOT NULL PRIMARY KEY,
  "user_id" TEXT NOT NULL,
  "email_normalized" TEXT NOT NULL,
  "email_display" TEXT NOT NULL,
  "is_primary" BOOLEAN NOT NULL DEFAULT false,
  "is_verified" BOOLEAN NOT NULL DEFAULT false,
  "verified_at" DATETIME,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" DATETIME NOT NULL,
  CONSTRAINT "user_emails_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "user_phones" (
  "phone_id" TEXT NOT NULL PRIMARY KEY,
  "user_id" TEXT NOT NULL,
  "phone_e164" TEXT NOT NULL,
  "is_primary" BOOLEAN NOT NULL DEFAULT false,
  "is_verified" BOOLEAN NOT NULL DEFAULT false,
  "verified_at" DATETIME,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" DATETIME NOT NULL,
  CONSTRAINT "user_phones_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "password_credentials" (
  "credential_id" TEXT NOT NULL PRIMARY KEY,
  "user_id" TEXT NOT NULL,
  "password_hash" TEXT NOT NULL,
  "hash_algorithm" TEXT NOT NULL,
  "hash_params_json" TEXT NOT NULL,
  "password_version" INTEGER NOT NULL DEFAULT 1,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" DATETIME NOT NULL,
  "last_changed_at" DATETIME NOT NULL,
  "must_change" BOOLEAN NOT NULL DEFAULT false,
  CONSTRAINT "password_credentials_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "oauth_clients" (
  "client_id" TEXT NOT NULL PRIMARY KEY,
  "client_name" TEXT NOT NULL,
  "client_type" TEXT NOT NULL,
  "status" TEXT NOT NULL,
  "redirect_uris_json" TEXT NOT NULL,
  "allowed_scopes_json" TEXT NOT NULL,
  "allowed_grant_types_json" TEXT NOT NULL,
  "token_endpoint_auth_method" TEXT NOT NULL,
  "client_secret_hash" TEXT,
  "jwks_uri" TEXT,
  "pkce_required" BOOLEAN NOT NULL DEFAULT false,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" DATETIME NOT NULL
);

CREATE TABLE "authorization_codes" (
  "code_id" TEXT NOT NULL PRIMARY KEY,
  "code_hash" TEXT NOT NULL,
  "user_id" TEXT NOT NULL,
  "client_id" TEXT NOT NULL,
  "redirect_uri" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "code_challenge" TEXT NOT NULL,
  "code_challenge_method" TEXT NOT NULL,
  "nonce" TEXT,
  "state_hash" TEXT,
  "session_id" TEXT NOT NULL,
  "device_id" TEXT,
  "expires_at" DATETIME NOT NULL,
  "consumed_at" DATETIME,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "authorization_codes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "authorization_codes_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("client_id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "authorization_codes_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "sessions" ("session_id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "sessions" (
  "session_id" TEXT NOT NULL PRIMARY KEY,
  "user_id" TEXT NOT NULL,
  "client_id" TEXT NOT NULL,
  "device_id" TEXT,
  "status" TEXT NOT NULL,
  "auth_time" DATETIME NOT NULL,
  "last_seen_at" DATETIME,
  "expires_at" DATETIME,
  "ip_hash" TEXT,
  "user_agent_hash" TEXT,
  "aal" INTEGER NOT NULL DEFAULT 1,
  "amr_json" TEXT NOT NULL,
  "risk_level" TEXT NOT NULL DEFAULT 'normal',
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "revoked_at" DATETIME,
  "revoke_reason" TEXT,
  CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "sessions_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("client_id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "sessions_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("device_id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE "refresh_token_families" (
  "family_id" TEXT NOT NULL PRIMARY KEY,
  "user_id" TEXT NOT NULL,
  "client_id" TEXT NOT NULL,
  "session_id" TEXT NOT NULL,
  "device_id" TEXT,
  "status" TEXT NOT NULL,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "revoked_at" DATETIME,
  "revoke_reason" TEXT,
  CONSTRAINT "refresh_token_families_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "refresh_token_families_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("client_id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "refresh_token_families_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "sessions" ("session_id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "refresh_token_families_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("device_id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE TABLE "refresh_tokens" (
  "token_id" TEXT NOT NULL PRIMARY KEY,
  "family_id" TEXT NOT NULL,
  "token_hash" TEXT NOT NULL,
  "status" TEXT NOT NULL,
  "issued_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expires_at" DATETIME NOT NULL,
  "consumed_at" DATETIME,
  "replaced_by_token_id" TEXT,
  "ip_hash" TEXT,
  "user_agent_hash" TEXT,
  CONSTRAINT "refresh_tokens_family_id_fkey" FOREIGN KEY ("family_id") REFERENCES "refresh_token_families" ("family_id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "access_token_jti" (
  "jti" TEXT NOT NULL PRIMARY KEY,
  "user_id" TEXT NOT NULL,
  "session_id" TEXT NOT NULL,
  "client_id" TEXT NOT NULL,
  "expires_at" DATETIME NOT NULL,
  "revoked_at" DATETIME,
  "revoke_reason" TEXT
);

CREATE TABLE "devices" (
  "device_id" TEXT NOT NULL PRIMARY KEY,
  "user_id" TEXT NOT NULL,
  "status" TEXT NOT NULL,
  "platform" TEXT NOT NULL,
  "device_name" TEXT,
  "app_version" TEXT,
  "os_version" TEXT,
  "public_signing_key" TEXT,
  "key_algorithm" TEXT,
  "device_certificate" TEXT,
  "push_token_hash" TEXT,
  "first_seen_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "last_seen_at" DATETIME,
  "revoked_at" DATETIME,
  "revoke_reason" TEXT,
  "risk_score" INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT "devices_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "verification_challenges" (
  "challenge_id" TEXT NOT NULL PRIMARY KEY,
  "user_id" TEXT,
  "identifier_hash" TEXT,
  "challenge_type" TEXT NOT NULL,
  "challenge_hash" TEXT NOT NULL,
  "purpose" TEXT NOT NULL,
  "status" TEXT NOT NULL,
  "attempt_count" INTEGER NOT NULL DEFAULT 0,
  "max_attempts" INTEGER NOT NULL DEFAULT 5,
  "expires_at" DATETIME NOT NULL,
  "consumed_at" DATETIME,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "mfa_factors" (
  "factor_id" TEXT NOT NULL PRIMARY KEY,
  "user_id" TEXT NOT NULL,
  "factor_type" TEXT NOT NULL,
  "status" TEXT NOT NULL,
  "display_name" TEXT,
  "secret_encrypted" TEXT,
  "phone_id" TEXT,
  "email_id" TEXT,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "verified_at" DATETIME,
  "last_used_at" DATETIME,
  "revoked_at" DATETIME
);

CREATE TABLE "passkey_credentials" (
  "credential_id" TEXT NOT NULL PRIMARY KEY,
  "user_id" TEXT NOT NULL,
  "credential_id_base64url" TEXT NOT NULL,
  "public_key" TEXT NOT NULL,
  "sign_count" INTEGER NOT NULL DEFAULT 0,
  "transports_json" TEXT,
  "aaguid" TEXT,
  "backup_eligible" BOOLEAN,
  "backup_state" BOOLEAN,
  "status" TEXT NOT NULL,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "last_used_at" DATETIME,
  "revoked_at" DATETIME
);

CREATE TABLE "audit_events" (
  "event_id" TEXT NOT NULL PRIMARY KEY,
  "event_type" TEXT NOT NULL,
  "user_id" TEXT,
  "session_id" TEXT,
  "device_id" TEXT,
  "client_id" TEXT,
  "request_id" TEXT,
  "ip_hash" TEXT,
  "user_agent_hash" TEXT,
  "result" TEXT NOT NULL,
  "risk_level" TEXT,
  "metadata_json" TEXT,
  "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX "user_emails_email_normalized_key" ON "user_emails"("email_normalized");
CREATE INDEX "user_emails_user_id_idx" ON "user_emails"("user_id");
CREATE UNIQUE INDEX "user_phones_phone_e164_key" ON "user_phones"("phone_e164");
CREATE INDEX "user_phones_user_id_idx" ON "user_phones"("user_id");
CREATE INDEX "password_credentials_user_id_idx" ON "password_credentials"("user_id");
CREATE UNIQUE INDEX "authorization_codes_code_hash_key" ON "authorization_codes"("code_hash");
CREATE INDEX "authorization_codes_user_id_idx" ON "authorization_codes"("user_id");
CREATE INDEX "authorization_codes_client_id_idx" ON "authorization_codes"("client_id");
CREATE INDEX "authorization_codes_session_id_idx" ON "authorization_codes"("session_id");
CREATE INDEX "sessions_user_id_idx" ON "sessions"("user_id");
CREATE INDEX "sessions_client_id_idx" ON "sessions"("client_id");
CREATE INDEX "sessions_device_id_idx" ON "sessions"("device_id");
CREATE INDEX "refresh_token_families_user_id_idx" ON "refresh_token_families"("user_id");
CREATE INDEX "refresh_token_families_session_id_idx" ON "refresh_token_families"("session_id");
CREATE INDEX "refresh_token_families_device_id_idx" ON "refresh_token_families"("device_id");
CREATE UNIQUE INDEX "refresh_tokens_token_hash_key" ON "refresh_tokens"("token_hash");
CREATE INDEX "refresh_tokens_family_id_idx" ON "refresh_tokens"("family_id");
CREATE INDEX "refresh_tokens_status_idx" ON "refresh_tokens"("status");
CREATE INDEX "access_token_jti_session_id_idx" ON "access_token_jti"("session_id");
CREATE INDEX "devices_user_id_idx" ON "devices"("user_id");
CREATE INDEX "verification_challenges_user_id_idx" ON "verification_challenges"("user_id");
CREATE INDEX "verification_challenges_identifier_hash_idx" ON "verification_challenges"("identifier_hash");
CREATE INDEX "verification_challenges_status_idx" ON "verification_challenges"("status");
CREATE INDEX "mfa_factors_user_id_idx" ON "mfa_factors"("user_id");
CREATE UNIQUE INDEX "passkey_credentials_credential_id_base64url_key" ON "passkey_credentials"("credential_id_base64url");
CREATE INDEX "passkey_credentials_user_id_idx" ON "passkey_credentials"("user_id");
CREATE INDEX "audit_events_event_type_idx" ON "audit_events"("event_type");
CREATE INDEX "audit_events_user_id_idx" ON "audit_events"("user_id");
CREATE INDEX "audit_events_created_at_idx" ON "audit_events"("created_at");

PRAGMA foreign_key_check;
PRAGMA foreign_keys=ON;
