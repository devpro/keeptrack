#!/usr/bin/env node
/*
 * Sets the `role` custom claim of a Firebase user, or shows the claims it carries.
 *
 * Usage:
 *   node scripts/firebase-user-role.js <service-account.json> <email-or-uid> [member|admin]
 *   node scripts/firebase-user-role.js <service-account.json> <email-or-uid> --show
 *
 * The role defaults to member.
 * A claim reaches the app at the user's next sign-in, since it is embedded in the ID token.
 *
 * Granting a role needs the project's service account, unlike creating a user (scripts/firebase-create-user.js).
 * It calls the Identity Toolkit REST API directly, with an OAuth token the service account signs itself,
 * so the script needs no npm package and runs on a bare Node.js.
 * The custom attributes are replaced as a whole, the same as the Admin SDK's setCustomUserClaims.
 *
 * Reference: https://cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/update
 */

const crypto = require('node:crypto');
const fs = require('node:fs');

const [serviceAccountPath, userIdentifier, roleArgument] = process.argv.slice(2);

if (!serviceAccountPath || !userIdentifier) {
    process.stderr.write('Usage: node scripts/firebase-user-role.js <service-account.json> <email-or-uid> [member|admin|--show]\n');
    process.exit(1);
}

const showOnly = roleArgument === '--show';
const role = showOnly ? null : roleArgument ?? 'member';
const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, 'utf8'));
const accountsUrl = `https://identitytoolkit.googleapis.com/v1/projects/${serviceAccount.project_id}/accounts`;

async function getAccessToken() {
    const now = Math.floor(Date.now() / 1000);
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({
        iss: serviceAccount.client_email,
        scope: 'https://www.googleapis.com/auth/identitytoolkit',
        aud: 'https://oauth2.googleapis.com/token',
        iat: now,
        exp: now + 600,
    })}`;
    const signature = crypto.sign('RSA-SHA256', Buffer.from(unsigned), serviceAccount.private_key).toString('base64url');

    const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${signature}` }),
    });
    const body = await response.json();
    if (!response.ok) {
        throw new Error(`Google refused the service account: ${body.error_description ?? body.error ?? response.statusText}`);
    }
    return body.access_token;
}

async function call(accessToken, action, payload) {
    const response = await fetch(`${accountsUrl}:${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
        throw new Error(`Firebase rejected ${action}: ${body.error?.message ?? response.statusText}`);
    }
    return body;
}

async function lookUp(accessToken) {
    const query = userIdentifier.includes('@') ? { email: [userIdentifier] } : { localId: [userIdentifier] };
    const user = (await call(accessToken, 'lookup', query)).users?.[0];
    if (!user) {
        throw new Error(`No user matches ${userIdentifier}.`);
    }
    return user;
}

async function main() {
    const accessToken = await getAccessToken();
    const user = await lookUp(accessToken);

    if (!showOnly) {
        await call(accessToken, 'update', { localId: user.localId, customAttributes: JSON.stringify({ role }) });
        process.stdout.write(`Set role '${role}' on ${user.email ?? user.localId}.\n`);
    }

    const current = showOnly ? user : await lookUp(accessToken);
    process.stdout.write(`uid:    ${current.localId}\n`);
    process.stdout.write(`email:  ${current.email ?? ''}\n`);
    process.stdout.write(`claims: ${current.customAttributes ?? '{}'}\n`);
}

main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
});
