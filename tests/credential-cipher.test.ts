/** At-rest encryption of the provider credential file. */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { after, describe, it } from "node:test";
import { createAesCipher, isEncryptedEnvelope } from "../src/store/credential-cipher.ts";
import { createProviderCredentialStore } from "../src/store/provider-credentials.ts";

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "lh-cipher-"));
after(() => fs.rmSync(TMP, { recursive: true, force: true }));
let n = 0;
const fresh = () => path.join(TMP, `case${n++}`, "creds", "credentials.json");
const oauth = () => ({ type: "oauth" as const, access: "SECRET-ACCESS", refresh: "SECRET-REFRESH", expires: 123 });

describe("credential cipher", () => {
	it("round-trips and rejects tampering or a wrong key", () => {
		const c = createAesCipher(randomBytes(32));
		const env = c.encrypt("hello");
		assert.ok(isEncryptedEnvelope(env));
		assert.equal(c.decrypt(env), "hello");
		assert.throws(() => createAesCipher(randomBytes(32)).decrypt(env));
		const o = JSON.parse(env);
		o.data = Buffer.from("x".repeat(5)).toString("base64");
		assert.throws(() => c.decrypt(JSON.stringify(o)));
	});

	it("store writes ciphertext only; reads back through the cipher", async () => {
		const file = fresh();
		const cipher = createAesCipher(randomBytes(32));
		const s = createProviderCredentialStore(file, { cipher });
		await s.modify("subscription-xai", async () => oauth());
		const raw = fs.readFileSync(file, "utf-8");
		assert.ok(!raw.includes("SECRET-ACCESS") && !raw.includes("SECRET-REFRESH"));
		assert.equal(s.peek("subscription-xai")?.type, "oauth");
		assert.equal((await s.read("subscription-xai") as { access: string }).access, "SECRET-ACCESS");
	});

	it("encryptAtRest upgrades an existing plaintext file", async () => {
		const file = fresh();
		await createProviderCredentialStore(file).modify("subscription-xai", async () => oauth());
		assert.ok(fs.readFileSync(file, "utf-8").includes("SECRET-ACCESS"));
		const cipher = createAesCipher(randomBytes(32));
		const s = createProviderCredentialStore(file, { cipher });
		assert.equal(s.has("subscription-xai"), true); // plaintext still readable pre-upgrade
		await (s as unknown as { encryptAtRest(): Promise<void> }).encryptAtRest();
		assert.ok(!fs.readFileSync(file, "utf-8").includes("SECRET-ACCESS"));
		assert.equal(s.has("subscription-xai"), true);
	});

	it("an encrypted file fails closed without a key and is never overwritten", async () => {
		const file = fresh();
		await createProviderCredentialStore(file, { cipher: createAesCipher(randomBytes(32)) }).modify("p1", async () => oauth());
		const before = fs.readFileSync(file, "utf-8");
		const plain = createProviderCredentialStore(file);
		assert.equal(plain.has("p1"), false);
		await assert.rejects(plain.read("p1"));
		await assert.rejects(plain.modify("p2", async () => oauth()));
		assert.equal(fs.readFileSync(file, "utf-8"), before);
		const wrong = createProviderCredentialStore(file, { cipher: createAesCipher(randomBytes(32)) });
		await assert.rejects(wrong.read("p1"));
		assert.equal(fs.readFileSync(file, "utf-8"), before);
	});
});
