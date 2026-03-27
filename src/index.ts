import { handleDiscovery, handleAuthorize, handleToken, handleJwks } from './oidc';
import { handleAdmin } from './admin';

export interface Env {
	DB: D1Database;
	ADMIN_PASSWORD: string;
	CLIENT_ID: string;
	CLIENT_SECRET: string;
	SIGNING_KEY: string;
	ALLOWED_REDIRECT_URIS: string;
}

const SECURITY_HEADERS: Record<string, string> = {
	'X-Content-Type-Options': 'nosniff',
	'X-Frame-Options': 'DENY',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
};

const CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; form-action 'self'; frame-ancestors 'none'";

function addSecurityHeaders(response: Response): Response {
	const contentType = response.headers.get('Content-Type') ?? '';
	const newResponse = new Response(response.body, response);
	for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
		newResponse.headers.set(k, v);
	}
	if (contentType.includes('text/html')) {
		newResponse.headers.set('Content-Security-Policy', CSP);
	}
	return newResponse;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		const path = url.pathname;

		try {
			let response: Response;

			if (path === '/.well-known/openid-configuration') {
				response = handleDiscovery(request, env);
			} else if (path === '/authorize' || path.startsWith('/authorize/')) {
				response = await handleAuthorize(request, env);
			} else if (path === '/token' && request.method === 'POST') {
				response = await handleToken(request, env);
			} else if (path === '/jwks') {
				response = await handleJwks(request, env);
			} else if (path.startsWith('/admin')) {
				response = await handleAdmin(request, env);
			} else {
				response = new Response('Not Found', { status: 404 });
			}

			return addSecurityHeaders(response);
		} catch (err) {
			console.error(err);
			return addSecurityHeaders(new Response('Internal Server Error', { status: 500 }));
		}
	},
} satisfies ExportedHandler<Env>;
