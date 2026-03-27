const ALG = "RSASSA-PKCS1-v1_5";
const HASH = "SHA-256";
const KEY_SIZE = 2048;
const KID = "default";

export function base64urlEncode(data: ArrayBuffer | Uint8Array | string): string {
  let bytes: Uint8Array;
  if (typeof data === "string") {
    bytes = new TextEncoder().encode(data);
  } else if (data instanceof ArrayBuffer) {
    bytes = new Uint8Array(data);
  } else {
    bytes = data;
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export async function generateKeyPair(): Promise<{
  privateKeyJwk: string;
  publicKeyJwk: JsonWebKey;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: ALG, modulusLength: KEY_SIZE, publicExponent: new Uint8Array([1, 0, 1]), hash: HASH },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;

  const rawPrivate = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const privateJwk = { ...(rawPrivate as unknown as Record<string, unknown>), kid: KID, alg: "RS256", use: "sig" };

  const rawPublic = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const publicJwk = { ...(rawPublic as unknown as Record<string, unknown>), kid: KID, alg: "RS256", use: "sig" };

  return {
    privateKeyJwk: JSON.stringify(privateJwk),
    publicKeyJwk: publicJwk as unknown as JsonWebKey,
  };
}

export async function importPrivateKey(jwkString: string): Promise<CryptoKey> {
  const jwk: JsonWebKey = JSON.parse(jwkString);
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: ALG, hash: HASH },
    false,
    ["sign"]
  );
}

export async function signJwt(
  payload: Record<string, unknown>,
  privateKeyJwk: string
): Promise<string> {
  const header = { alg: "RS256", typ: "JWT", kid: KID };

  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const privateKey = await importPrivateKey(privateKeyJwk);
  const signatureBuffer = await crypto.subtle.sign(
    ALG,
    privateKey,
    new TextEncoder().encode(signingInput)
  );

  const encodedSignature = base64urlEncode(signatureBuffer);
  return `${signingInput}.${encodedSignature}`;
}

const PRIVATE_FIELDS = new Set(["d", "p", "q", "dp", "dq", "qi"]);

export async function getJwks(
  privateKeyJwk: string
): Promise<{ keys: Record<string, unknown>[] }> {
  const privateJwk = JSON.parse(privateKeyJwk) as Record<string, unknown>;

  const publicJwk: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(privateJwk)) {
    if (!PRIVATE_FIELDS.has(k)) {
      publicJwk[k] = v;
    }
  }
  publicJwk.key_ops = ["verify"];

  return { keys: [publicJwk] };
}
