/**
 * At-rest encryption for the provider credential file.
 *
 * The file body becomes an AES-256-GCM envelope
 * {version:2, enc:"aes-256-gcm", iv, tag, data} (base64). The 32-byte key is
 * NOT stored next to the file: on macOS it lives in the login Keychain
 * (generic password, service "learnharness-credentials"), so a copied,
 * backed-up or synced credential file is useless without the Keychain.
 *
 * Where no key source exists (non-macOS, `security` missing or failing),
 * keychainCipher() returns undefined and the store keeps its plaintext
 * 0600 format. An encrypted file with no key available fails closed; it is
 * never overwritten.
 *
 * Limits: any process running as the same user can ask the Keychain for the
 * key (macOS may prompt). The key is passed to `security` as an argument for
 * the instant it is created, visible to `ps`. This defends the file at rest,
 * not a compromised user session.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";

export interface CredentialCipher {
	encrypt(plaintext: string): string;
	/** Throws on tampering or a wrong key. */
	decrypt(envelope: string): string;
}

const ALG = "aes-256-gcm";

export function createAesCipher(key: Buffer): CredentialCipher {
	if (key.length !== 32) throw new Error("Credential key must be 32 bytes.");
	return {
		encrypt(plaintext) {
			const iv = randomBytes(12);
			const c = createCipheriv(ALG, key, iv);
			const data = Buffer.concat([c.update(plaintext, "utf-8"), c.final()]);
			return `${JSON.stringify({
				version: 2,
				enc: ALG,
				iv: iv.toString("base64"),
				tag: c.getAuthTag().toString("base64"),
				data: data.toString("base64"),
			})}\n`;
		},
		decrypt(envelope) {
			const e = JSON.parse(envelope) as Record<string, unknown>;
			if (e.version !== 2 || e.enc !== ALG) throw new Error("Unsupported envelope.");
			const d = createDecipheriv(ALG, key, Buffer.from(String(e.iv), "base64"));
			d.setAuthTag(Buffer.from(String(e.tag), "base64"));
			return Buffer.concat([d.update(Buffer.from(String(e.data), "base64")), d.final()]).toString("utf-8");
		},
	};
}

/** True when the text is a v2 encrypted envelope (does not decrypt it). */
export function isEncryptedEnvelope(text: string): boolean {
	try {
		const o = JSON.parse(text) as { version?: unknown; enc?: unknown };
		return o?.version === 2 && o?.enc === ALG;
	} catch {
		return false;
	}
}

const SERVICE = "learnharness-credentials";
const ACCOUNT = "master-key";
const NOT_FOUND = 44;
const ALREADY_EXISTS = 45;

function security(args: string[]): { ok: boolean; status: number; out: string } {
	try {
		const out = execFileSync("/usr/bin/security", args, { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], timeout: 15_000 });
		return { ok: true, status: 0, out: out.trim() };
	} catch (e) {
		return { ok: false, status: (e as { status?: number }).status ?? -1, out: "" };
	}
}

function readKey(): Buffer | undefined {
	const r = security(["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"]);
	return r.ok && /^[0-9a-f]{64}$/.test(r.out) ? Buffer.from(r.out, "hex") : undefined;
}

let cached: CredentialCipher | undefined | null = null;

/** The Keychain-backed cipher, created once per process; undefined if unavailable. */
export function keychainCipher(): CredentialCipher | undefined {
	if (cached !== null) return cached;
	cached = undefined;
	// Tests never touch the real Keychain; LH_PLAINTEXT_CREDENTIALS=1 opts out explicitly.
	if (process.platform !== "darwin" || process.env.NODE_ENV === "test" || process.env.LH_PLAINTEXT_CREDENTIALS === "1") return cached;
	let key = readKey();
	if (!key) {
		const probe = security(["find-generic-password", "-s", SERVICE, "-a", ACCOUNT]);
		if (probe.status !== NOT_FOUND && probe.ok === false) return cached; // Keychain unusable: stay plaintext
		const fresh = randomBytes(32);
		const add = security(["add-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w", fresh.toString("hex")]);
		// Lost a creation race to another process: use the winner's key.
		key = add.ok ? fresh : add.status === ALREADY_EXISTS ? readKey() : undefined;
	}
	if (key) cached = createAesCipher(key);
	return cached;
}
