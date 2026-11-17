/** Platform / common infra ports that must not be reserved as “free app” slots. */
export const PLATFORM_FIXED_PORTS = new Set([22, 80, 443, 2096, 3306, 4000, 5432, 6379, 27017]);

/** Suggested allocation window (mirrors vercel-clone RANGE_* intent; previews use 20000+ separately). */
export const APP_PORT_RANGE = Object.freeze({ start: 3000, end: 19999 });
