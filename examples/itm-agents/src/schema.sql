-- SQLite mirror of the slice of ITM's Prisma schema (itm-backend src/database/schema.prisma, local copy
-- ITM's Prisma schema) that agent authorization touches. Column names follow Prisma field names.
-- Tables marked PROPOSED do not exist in ITM today.

-- model Brand (tenant). Real model has ~227 fields; we keep identity fields.
CREATE TABLE IF NOT EXISTS Brand (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL);
-- model AdminUser
CREATE TABLE IF NOT EXISTS AdminUser (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, revokedAt TEXT);
-- enum AdminBrandRole { OWNER ADMIN AGENT }; model AdminUserBrand (@@unique([adminUserId, brandId])).
-- authorizationVersion: described in itm-backend docs/partner-mcp-oauth.md (bumped on access loss); not in our schema copy.
-- momentUid: OPTIONAL/FUTURE knob (off by default). Today AGENT staff are brand-wide (BrandMemberGuard); only read when momentPinning is on.
CREATE TABLE IF NOT EXISTS AdminUserBrand (
  id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, adminUserId INTEGER NOT NULL REFERENCES AdminUser(id), brandId INTEGER NOT NULL REFERENCES Brand(id),
  role TEXT NOT NULL CHECK (role IN ('OWNER','ADMIN','AGENT')), revokedAt TEXT, scheduledDeactivationAt TEXT,
  authorizationVersion INTEGER NOT NULL DEFAULT 1, momentUid TEXT, UNIQUE (adminUserId, brandId));
-- model Moment (= event). isPrivate forced true for agent-created moments (itm-agent create_moment).
CREATE TABLE IF NOT EXISTS Moment (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, brandId INTEGER NOT NULL REFERENCES Brand(id), name TEXT NOT NULL, slug TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '', startDate TEXT NOT NULL, timezone TEXT NOT NULL DEFAULT 'America/New_York', isPrivate INTEGER NOT NULL DEFAULT 1, publishedAt TEXT,
  createdByAdminUserId INTEGER, createIdempotencyKey TEXT, UNIQUE (brandId, slug));
-- model TicketTier (price/facilityFee in cents, supply/remainingSupply)
CREATE TABLE IF NOT EXISTS TicketTier (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, momentId INTEGER NOT NULL REFERENCES Moment(id), name TEXT NOT NULL,
  price INTEGER NOT NULL, supply INTEGER NOT NULL, remainingSupply INTEGER NOT NULL, archivedAt TEXT);
-- model Ticket + model TicketCheckIn (checkedInBy AdminUser)
CREATE TABLE IF NOT EXISTS Ticket (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, ticketTierId INTEGER NOT NULL REFERENCES TicketTier(id), holderName TEXT NOT NULL, holderEmail TEXT, holderPhone TEXT);
CREATE TABLE IF NOT EXISTS TicketCheckIn (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, ticketId INTEGER NOT NULL REFERENCES Ticket(id), checkedInByAdminUserId INTEGER, agentGrantUid TEXT, createdAt TEXT NOT NULL, voidedAt TEXT);
-- model Plan / PlanBudget / PlanBudgetLine (amounts in minor units) / PlanChangeProposal (PREPARED -> applied)
CREATE TABLE IF NOT EXISTS Plan (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, brandId INTEGER NOT NULL REFERENCES Brand(id), name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'DRAFT', revision INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS PlanBudgetLine (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, planId INTEGER NOT NULL REFERENCES Plan(id), name TEXT NOT NULL, vendorLabel TEXT, plannedUnitAmountMinor INTEGER NOT NULL, quantity REAL NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS PlanChangeProposal (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, planId INTEGER NOT NULL REFERENCES Plan(id), status TEXT NOT NULL, payload TEXT NOT NULL, expiresAt TEXT NOT NULL, createdAt TEXT NOT NULL);
-- model Venue (descriptive only, no inventory)
CREATE TABLE IF NOT EXISTS Venue (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, name TEXT NOT NULL, city TEXT NOT NULL, capacity INTEGER);
-- model BrandAgentEmailSendBatch (AgentMail sends; 1-10 recipients; operator CC'd)
CREATE TABLE IF NOT EXISTS BrandAgentEmailSendBatch (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, brandId INTEGER NOT NULL, status TEXT NOT NULL, recipients TEXT NOT NULL, subject TEXT NOT NULL,
  adminUserUid TEXT, agentGrantUid TEXT, createdAt TEXT NOT NULL);
-- PROPOSED (brand-services-marketplace-plan.md v1.12, "planned, not started"): listings and quotes for booth/vendor space.
CREATE TABLE IF NOT EXISTS BrandServiceListing (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, title TEXT NOT NULL, city TEXT NOT NULL, kind TEXT NOT NULL, description TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS BrandServiceQuote (id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, brandId INTEGER NOT NULL, listingId INTEGER NOT NULL, amountCents INTEGER NOT NULL, status TEXT NOT NULL, createdAt TEXT NOT NULL);

-- ===================== PROPOSED: agent connection grants =====================
CREATE TABLE IF NOT EXISTS AgentGrant (
  id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL, brandId INTEGER NOT NULL REFERENCES Brand(id),
  grantorAdminUserId INTEGER NOT NULL REFERENCES AdminUser(id),        -- the human the agent acts for (act chain root)
  grantorRoleAtGrant TEXT NOT NULL, grantorAuthorizationVersion INTEGER NOT NULL,
  name TEXT NOT NULL,                                                  -- 'booking-bot', 'marketing-bot', ...
  momentUid TEXT,                                                      -- set when the grantor is moment-scoped (AGENT staff)
  scopes TEXT NOT NULL,                                                -- JSON array of itm:* scopes
  tools TEXT NOT NULL,                                                 -- JSON array of tool entries (resolved at consent)
  overlay TEXT NOT NULL,                                               -- generated mcp-rbac.yaml overlay (v1)
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','PAUSED','REVOKED')),
  epoch INTEGER NOT NULL DEFAULT 1, dpopJkt TEXT,                      -- key the tokens are bound to
  createdAt TEXT NOT NULL, expiresAt TEXT NOT NULL, revokedAt TEXT, revokedByAdminUserId INTEGER,
  UNIQUE (brandId, grantorAdminUserId, name));
CREATE TABLE IF NOT EXISTS AgentGrantToken (id INTEGER PRIMARY KEY, tokenHash TEXT UNIQUE NOT NULL, grantId INTEGER NOT NULL REFERENCES AgentGrant(id), grantEpoch INTEGER NOT NULL, jkt TEXT NOT NULL, expiresAt TEXT NOT NULL, revokedAt TEXT);
CREATE TABLE IF NOT EXISTS AgentGrantAuthCode (codeHash TEXT PRIMARY KEY, grantId INTEGER NOT NULL, codeChallenge TEXT NOT NULL, redirectUri TEXT NOT NULL, dpopJkt TEXT NOT NULL, expiresAt TEXT NOT NULL, consumedAt TEXT);
CREATE TABLE IF NOT EXISTS AgentGrantApproval (uid TEXT PRIMARY KEY, grantId INTEGER NOT NULL, tool TEXT NOT NULL, inputHash TEXT NOT NULL, summary TEXT NOT NULL, status TEXT NOT NULL, requestedAt TEXT NOT NULL, expiresAt TEXT NOT NULL, decidedAt TEXT, decidedByAdminUserId INTEGER);
CREATE TABLE IF NOT EXISTS BudgetEvent (id INTEGER PRIMARY KEY, key TEXT NOT NULL, at INTEGER NOT NULL, amount REAL NOT NULL);
CREATE INDEX IF NOT EXISTS BudgetEvent_key_at ON BudgetEvent(key, at);
CREATE TABLE IF NOT EXISTS DpopJti (jti TEXT PRIMARY KEY, iat INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS AdminSession (tokenHash TEXT PRIMARY KEY, adminUserId INTEGER NOT NULL, expiresAt TEXT NOT NULL);
-- Hash-chained action audit (extends AgentActionLog with grant + act chain + decision).
CREATE TABLE IF NOT EXISTS AgentActionLog (seq INTEGER PRIMARY KEY, at TEXT NOT NULL, brandUid TEXT, adminUserUid TEXT, grantUid TEXT, agentName TEXT, actChain TEXT NOT NULL,
  tool TEXT NOT NULL, inputHash TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, baseRule TEXT, overlayRule TEXT, prevHash TEXT NOT NULL, hash TEXT NOT NULL);
