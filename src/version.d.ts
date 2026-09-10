export const APP_NAME: string;
export const VERSION: string;
export const DEFAULT_SSH_SERVER_VERSION: string;

export function getVersion(): string;
export function getDefaultSshServerVersion(): string;
export function formatSshServerVersion(customVersion?: string): string;
