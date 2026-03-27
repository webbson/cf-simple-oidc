import { handleDiscovery, handleAuthorize, handleToken, handleJwks } from './oidc';
import { handleAdmin } from './admin';

export interface Env {
	DB: D1Database;
	ADMIN_PASSWORD: string;
	CLIENT_ID: string;
	CLIENT_SECRET: string;
	SIGNING_KEY: string;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		const path = url.pathname;

		try {
			if (path === '/.well-known/openid-configuration') {
				return handleDiscovery(request, env);
			}

			if (path === '/authorize') {
				return handleAuthorize(request, env);
			}

			if (path === '/token' && request.method === 'POST') {
				return handleToken(request, env);
			}

			if (path === '/jwks') {
				return handleJwks(request, env);
			}

			if (path.startsWith('/admin')) {
				return handleAdmin(request, env);
			}

			return new Response('Not Found', { status: 404 });
		} catch (err) {
			const message = err instanceof Error ? err.message : 'Internal Server Error';
			return new Response(message, { status: 500 });
		}
	},
} satisfies ExportedHandler<Env>;
