import { describe, expect, it } from "bun:test";
import { sso } from "@better-auth/sso";
import { betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { isAuthEnabled } from "../src/env";
import {
	isClosedSignInPath,
	SIGN_IN_CLOSED_MESSAGE,
	signInClosed,
} from "../src/sign-in-gate";

const BASE_URL = "http://localhost:3001";

const before = createAuthMiddleware(async (ctx) => {
	await signInClosed(ctx);
});

const auth = betterAuth({
	baseURL: BASE_URL,
	secret: "sign-in-gate-spec-secret-32-chars",
	emailAndPassword: { enabled: false },
	hooks: { before },
	plugins: [sso({ organizationProvisioning: { disabled: true } })],
});

const call = (path: string, method: "GET" | "POST") =>
	auth.handler(
		new Request(`${BASE_URL}/api/auth${path}`, {
			method,
			headers: { "content-type": "application/json" },
			body: method === "POST" ? "{}" : undefined,
		}),
	);

describe("isAuthEnabled", () => {
	it("is on only for the literal true", () => {
		const previous = process.env.AUTH_ENABLED;

		try {
			delete process.env.AUTH_ENABLED;
			expect(isAuthEnabled()).toBe(false);

			process.env.AUTH_ENABLED = "false";
			expect(isAuthEnabled()).toBe(false);

			process.env.AUTH_ENABLED = "TRUE";
			expect(isAuthEnabled()).toBe(false);

			process.env.AUTH_ENABLED = "true";
			expect(isAuthEnabled()).toBe(true);
		} finally {
			if (previous === undefined) delete process.env.AUTH_ENABLED;
			else process.env.AUTH_ENABLED = previous;
		}
	});
});

describe("isClosedSignInPath", () => {
	it("closes social, SSO, and callback routes", () => {
		expect(isClosedSignInPath("/sign-in/social")).toBe(true);
		expect(isClosedSignInPath("/sign-in/sso")).toBe(true);
		expect(isClosedSignInPath("/sign-in/oauth2")).toBe(true);
		expect(isClosedSignInPath("/sign-in/email")).toBe(true);
		expect(isClosedSignInPath("/sign-up/email")).toBe(true);
		expect(isClosedSignInPath("/callback/google")).toBe(true);
		expect(isClosedSignInPath("/callback/microsoft")).toBe(true);
		expect(isClosedSignInPath("/link-social")).toBe(true);
		expect(isClosedSignInPath("/sso/callback/okta")).toBe(true);
		expect(isClosedSignInPath("/sso/saml2/sp/acs/okta")).toBe(true);
	});

	it("leaves session, sign-out, and Slack connect open", () => {
		expect(isClosedSignInPath("/get-session")).toBe(false);
		expect(isClosedSignInPath("/sign-out")).toBe(false);
		expect(isClosedSignInPath("/ok")).toBe(false);
		expect(isClosedSignInPath("/oauth2/link")).toBe(false);
		expect(isClosedSignInPath("/oauth2/callback/slack")).toBe(false);
		expect(isClosedSignInPath("/sso/register")).toBe(false);
	});
});

describe("signInClosed", () => {
	it("refuses social sign-in while AUTH_ENABLED is not true", async () => {
		const previous = process.env.AUTH_ENABLED;
		delete process.env.AUTH_ENABLED;

		try {
			const response = await call("/sign-in/social", "POST");
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({
				message: SIGN_IN_CLOSED_MESSAGE,
			});
		} finally {
			if (previous === undefined) delete process.env.AUTH_ENABLED;
			else process.env.AUTH_ENABLED = previous;
		}
	});

	it("refuses the SSO sign-in and the provider callback", async () => {
		const previous = process.env.AUTH_ENABLED;
		delete process.env.AUTH_ENABLED;

		try {
			const start = await call("/sign-in/sso", "POST");
			const callback = await call("/sso/callback/okta", "GET");
			const google = await call("/callback/google", "GET");
			const link = await call("/link-social", "POST");

			expect(start.status).toBe(503);
			expect(callback.status).toBe(503);
			expect(google.status).toBe(503);
			expect(link.status).toBe(503);
		} finally {
			if (previous === undefined) delete process.env.AUTH_ENABLED;
			else process.env.AUTH_ENABLED = previous;
		}
	});

	it("still answers get-session and sign-out", async () => {
		const previous = process.env.AUTH_ENABLED;
		delete process.env.AUTH_ENABLED;

		try {
			const session = await call("/get-session", "GET");
			const signOut = await call("/sign-out", "POST");
			const slack = await call("/oauth2/link", "POST");

			expect(session.status).toBe(200);
			expect(signOut.status).not.toBe(503);
			expect(slack.status).not.toBe(503);
		} finally {
			if (previous === undefined) delete process.env.AUTH_ENABLED;
			else process.env.AUTH_ENABLED = previous;
		}
	});

	it("lets social sign-in through when AUTH_ENABLED is true", async () => {
		const previous = process.env.AUTH_ENABLED;
		process.env.AUTH_ENABLED = "true";

		try {
			const response = await call("/sign-in/social", "POST");
			expect(response.status).not.toBe(503);
		} finally {
			if (previous === undefined) delete process.env.AUTH_ENABLED;
			else process.env.AUTH_ENABLED = previous;
		}
	});
});
