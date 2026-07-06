import { initializeApp, cert } from "npm:firebase-admin/app";
import { getAuth } from "npm:firebase-admin/auth";
import path from "node:path";

// 1. Grab command line arguments
const [serviceAccountPath, userIdentifier] = Deno.args;

if (!serviceAccountPath || !userIdentifier) {
  console.error("❌ Error: Missing arguments.");
  console.log("Usage: deno run -A scripts/firebase-set-admin.js <path-to-json> <email-or-uid>");
  Deno.exit(1);
}

try {
  // 2. Read and parse the service account file natively
  const resolvedPath = path.resolve(serviceAccountPath);
  const jsonRaw = await Deno.readTextFile(resolvedPath);
  const serviceAccount = JSON.parse(jsonRaw);

  // 3. Initialize official Firebase Admin SDK using modern ESM functions
  initializeApp({
    credential: cert(serviceAccount)
  });

  // Get the Auth instance
  const auth = getAuth();

  let uid = userIdentifier;

  // 4. Resolve email to UID if necessary
  if (userIdentifier.includes('@')) {
    console.log(`🔍 Looking up user by email: ${userIdentifier}...`);
    const userRecord = await auth.getUserByEmail(userIdentifier);
    uid = userRecord.uid;
  }

  // 5. Set the custom claim
  console.log(`🚀 Setting admin role claim for UID: ${uid}...`);
  await auth.setCustomUserClaims(uid, { role: "admin" });

  console.log("%c✅ Successfully set admin claim!", "color: green; font-weight: bold;");

  // 6. Verify it worked
  const updatedUser = await auth.getUser(uid);
  console.log("Current custom claims:", updatedUser.customClaims);

} catch (error) {
  console.error(`❌ Error: ${error.message}`);
  Deno.exit(1);
}
