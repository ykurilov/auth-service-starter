import { createAuthHandlers } from '@/auth';

export const { GET, POST } = createAuthHandlers({ env: process.env });
