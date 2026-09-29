// Public configuration only. NEVER put an OpenRouter key here.
// Appwrite function domain (public, not a secret). Local `npm start` keeps using its own /api.
const local = ['localhost', '127.0.0.1'].includes(location.hostname);
export const API_BASE = local ? '' : 'https://6abb8be7000afba81fba.appwrite.network';
