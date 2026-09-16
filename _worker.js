import { AwsClient } from "aws4fetch";

const MIME = "application/vnd.git-lfs+json";
const EXPIRY_SECONDS = 300;
const MAX_BODY_BYTES = 256 * 1024;
const MAX_OBJECTS = 1000;
const HEX_SHA256 = /^[0-9a-f]{64}$/;
const USERNAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": MIME,
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

function fail(status, message, headers = {}) {
  throw json({ message }, status, headers);
}

function unauthorized() {
  fail(401, "Authentication required.", {
    "WWW-Authenticate": 'Basic realm="Git LFS", charset="UTF-8"',
  });
}

function isRecord(value) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value);
}

function loadConfig(env) {
  const required = [
    "B2_ENDPOINT",
    "B2_REGION",
    "B2_BUCKET",
    "B2_KEY_ID",
    "B2_APPLICATION_KEY",
    "LFS_USERS_JSON",
  ];

  for (const name of required) {
    if (typeof env[name] !== "string" || !env[name].trim()) {
      throw new Error("Missing server configuration.");
    }
  }

  if (!/^[a-z0-9-]+$/.test(env.B2_REGION)) {
    throw new Error("Invalid storage region.");
  }

  const endpoint = new URL(env.B2_ENDPOINT);
  const expectedOrigin =
    "https://s3." + env.B2_REGION + ".backblazeb2.com";

  if (
    endpoint.origin !== expectedOrigin ||
    endpoint.pathname !== "/" ||
    endpoint.search ||
    endpoint.hash ||
    endpoint.username ||
    endpoint.password
  ) {
    throw new Error("Invalid storage endpoint.");
  }

  if (!/^[A-Za-z0-9-]{6,63}$/.test(env.B2_BUCKET)) {
    throw new Error("Invalid storage bucket.");
  }

  const users = JSON.parse(env.LFS_USERS_JSON);

  if (!Array.isArray(users)) {
    throw new Error("Invalid user configuration.");
  }

  const names = new Set();
  const hashes = new Set();

  for (const user of users) {
    if (
      !isRecord(user) ||
      typeof user.username !== "string" ||
      !USERNAME.test(user.username) ||
      typeof user.tokenSha256 !== "string" ||
      !HEX_SHA256.test(user.tokenSha256) ||
      !Array.isArray(user.permissions) ||
      !user.permissions.every(
        (permission) =>
          permission === "download" || permission === "upload",
      ) ||
      names.has(user.username) ||
      hashes.has(user.tokenSha256)
    ) {
      throw new Error("Invalid user configuration.");
    }

    names.add(user.username);
    hashes.add(user.tokenSha256);
  }

  return {
    endpoint: endpoint.origin,
    bucket: env.B2_BUCKET,
    region: env.B2_REGION,
    accessKeyId: env.B2_KEY_ID,
    secretAccessKey: env.B2_APPLICATION_KEY,
    users,
  };
}

async function authenticate(req, users) {
  const header = req.headers.get("Authorization") || "";

  if (header.length > 1024) {
    unauthorized();
  }

  const match = /^Basic +([A-Za-z0-9+/]+={0,2})$/i.exec(header);

  if (!match) {
    unauthorized();
  }

  let decoded;

  try {
    decoded = atob(match[1]);
  } catch {
    unauthorized();
  }

  const separator = decoded.indexOf(":");

  if (separator < 1) {
    unauthorized();
  }

  const username = decoded.slice(0, separator);
  const token = decoded.slice(separator + 1);

  if (!USERNAME.test(username) || !HEX_SHA256.test(token)) {
    unauthorized();
  }

  const user = users.find((entry) => entry.username === username);
  const expectedHex = user?.tokenSha256 || "0".repeat(64);
  const expected = Uint8Array.from(
    expectedHex.match(/../g),
    (byte) => Number.parseInt(byte, 16),
  );

  const actual = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );

  const valid = crypto.subtle.timingSafeEqual(actual, expected);

  if (!valid || !user) {
    unauthorized();
  }

  return user;
}

async function readJson(req) {
  if (!req.body) {
    fail(400, "Request body is required.");
  }

  const reader = req.body.getReader();
  const chunks = [];
  let length = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) {
        break;
      }

      length += value.byteLength;

      if (length > MAX_BODY_BYTES) {
        await reader.cancel();
        fail(413, "Request body is too large.");
      }

      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(length);
  let offset = 0;

  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
  } catch {
    fail(400, "Invalid JSON body.");
  }
}

async function handle(req, env) {
  const url = new URL(req.url);

  if (url.protocol !== "https:") {
    fail(400, "HTTPS is required.");
  }

  if (url.pathname !== "/lfs/objects/batch") {
    fail(404, "Not found.");
  }

  if (url.search) {
    fail(400, "Query parameters are not supported.");
  }

  if (req.method !== "POST") {
    fail(405, "Method not allowed.", { Allow: "POST" });
  }

  const config = loadConfig(env);
  const user = await authenticate(req, config.users);
  const permissions = user.permissions;

  if (permissions.length === 0) {
    fail(403, "Access denied.");
  }

  const body = await readJson(req);

  if (!isRecord(body)) {
    fail(400, "Invalid batch request.");
  }

  const {
    operation,
    objects,
    hash_algo = "sha256",
    transfers,
  } = body;

  if (operation !== "upload" && operation !== "download") {
    fail(400, "Unsupported operation.");
  }

  if (!permissions.includes(operation)) {
    fail(403, "Access denied.");
  }

  if (hash_algo !== "sha256") {
    fail(409, "Only SHA-256 is supported.");
  }

  if (
    transfers !== undefined &&
    (!Array.isArray(transfers) || !transfers.includes("basic"))
  ) {
    fail(422, "The basic transfer adapter is required.");
  }

  if (!Array.isArray(objects)) {
    fail(400, "Objects must be an array.");
  }

  if (objects.length > MAX_OBJECTS) {
    fail(413, "Too many objects in one batch.");
  }

  for (const object of objects) {
    if (
      !isRecord(object) ||
      typeof object.oid !== "string" ||
      !HEX_SHA256.test(object.oid) ||
      !Number.isSafeInteger(object.size) ||
      object.size < 0
    ) {
      fail(422, "Invalid object OID or size.");
    }
  }

  const s3 = new AwsClient({
    accessKeyId: config.accessKeyId,
    secretAccessKey: config.secretAccessKey,
    service: "s3",
    region: config.region,
  });

  const results = await Promise.all(
    objects.map(async ({ oid, size }) => {
      const objectUrl = new URL(
        "/" + config.bucket + "/lfs/" + oid,
        config.endpoint,
      );

      objectUrl.searchParams.set(
        "X-Amz-Expires",
        String(EXPIRY_SECONDS),
      );

      const signed = await s3.sign(objectUrl.toString(), {
        method: operation === "upload" ? "PUT" : "GET",
        aws: { signQuery: true },
      });

      return {
        oid,
        size,
        authenticated: true,
        actions: {
          [operation]: {
            href: signed.url,
            expires_in: EXPIRY_SECONDS,
          },
        },
      };
    }),
  );

  return json({
    transfer: "basic",
    hash_algo: "sha256",
    objects: results,
  });
}

export default {
  async fetch(req, env) {
    try {
      return await handle(req, env);
    } catch (error) {
      if (error instanceof Response) {
        return error;
      }

      // Never log credentials, request headers, or signed URLs.
      return json({ message: "Internal server error." }, 500);
    }
  },
};
