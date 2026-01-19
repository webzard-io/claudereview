// Default values for the application
// These can be overridden by environment variables

export const DEFAULT_API_URL = 'http://192.168.17.244:31935';
export const DEFAULT_SITE_NAME = 'claudereview';

// Runtime values (prefer environment variables)
export const API_URL = process.env.CCSHARE_API_URL || DEFAULT_API_URL;
export const SITE_NAME = process.env.SITE_NAME || DEFAULT_SITE_NAME;

// Server-side values
export const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
export const SITE_HOST = BASE_URL.replace(/^https?:\/\//, '');
