#!/usr/bin/env node
/*
 * Creates a new Firebase user via the public accounts:signUp REST endpoint.
 *
 * Why this exists: the repository already has scripts/firebase-user-role.js to grant a role to an
 * *existing* user, but nothing creates one.
 * A second test account (e.g. FIREBASE_USERNAME2/FIREBASE_PASSWORD2, for a test that needs two distinct
 * signed-in identities) currently has to be created by hand in the Firebase console.
 *
 * Deliberately needs only the Web API key (FIREBASE_APIKEY), never a service account.
 * accounts:signUp is the same public endpoint a real "create account" form calls, so creating a user needs
 * no elevated privilege - only granting a role afterward does, which is why that stays a separate script
 * over the Admin SDK (scripts/firebase-user-role.js).
 *
 * Usage:
 *   FIREBASE_APIKEY=<web-api-key> node scripts/firebase-create-user.js
 *   FIREBASE_APIKEY=<web-api-key> node scripts/firebase-create-user.js someone@example.com
 *   FIREBASE_APIKEY=<web-api-key> node scripts/firebase-create-user.js someone@example.com "a specific password"
 *
 * Email and password are both optional - omitted, a random test address and a strong random password are
 * generated, the same shape End2EndFixture already uses for its own ephemeral e2e users.
 *
 * Reference: https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signUp
 */

const crypto = require('node:crypto');

const apiKey = process.env.FIREBASE_APIKEY;
if (!apiKey) {
    process.stderr.write('FIREBASE_APIKEY is not set. See CONTRIBUTING.md for where to find the project\'s Web API key.\n');
    process.exit(1);
}

const email = process.argv[2] ?? `keeptrack-test-${crypto.randomBytes(6).toString('hex')}@keeptrack.test`;
const password = process.argv[3] ?? `Kt-${crypto.randomBytes(9).toString('base64url')}!1`;

async function main() {
    const response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
    });

    const body = await response.json();

    if (!response.ok) {
        // Firebase's own error carries the actual reason (EMAIL_EXISTS, WEAK_PASSWORD, ...) - report that
        // rather than the bare HTTP status, the same "describe what the provider actually did" rule this
        // repository applies to every other third-party call.
        process.stderr.write(`Firebase rejected the sign-up: ${body.error?.message ?? response.statusText}\n`);
        process.exit(1);
    }

    process.stdout.write(`Created user ${email}\n`);
    process.stdout.write(`  uid:      ${body.localId}\n`);
    process.stdout.write(`  email:    ${email}\n`);
    process.stdout.write(`  password: ${password}\n`);
    process.stdout.write('\n');
    process.stdout.write('No role claim is set - a brand new user is a free-preview account by default.\n');
    process.stdout.write('To grant one (needs the project\'s service account JSON, see CONTRIBUTING.md\'s "Admin role" section):\n');
    process.stdout.write(`  deno run -A scripts/firebase-user-role.js <path-to-service-account.json> ${email} member\n`);
    process.stdout.write(`  deno run -A scripts/firebase-user-role.js <path-to-service-account.json> ${email} admin\n`);
}

main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
});
