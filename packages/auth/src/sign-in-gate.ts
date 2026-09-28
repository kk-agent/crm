import { APIError, createAuthMiddleware } from "better-auth/api";
import { isAuthEnabled } from "./env";

export const SIGN_IN_CLOSED_MESSAGE = "Sign-in is not available yet.";

const CLOSED_PREFIXES = [
	"/sign-in",
	"/sign-up",
	"/callback",
	"/link-social",
	"/sso/callback",
	"/sso/saml2/callback",
	"/sso/saml2/sp/acs",
] as const;

export function isClosedSignInPath(path: string): boolean {
	return CLOSED_PREFIXES.some(
		(prefix) => path === prefix || path.startsWith(`${prefix}/`),
	);
}

export function refuseClosedSignIn(path: string): void {
	if (isAuthEnabled()) return;
	if (!isClosedSignInPath(path)) return;

	throw new APIError("SERVICE_UNAVAILABLE", {
		message: SIGN_IN_CLOSED_MESSAGE,
	});
}

export const signInClosed = createAuthMiddleware(async (ctx) => {
	refuseClosedSignIn(ctx.path);
});
