import { createAuthHandlers } from '@/auth';

// Обработчики создаются при первом запросе, а не при загрузке файла:
// `next build` загружает маршрут без переменных AUTH_* и упал бы на проверке
// конфигурации.
let handlers: ReturnType<typeof createAuthHandlers> | undefined;
const auth = () => (handlers ??= createAuthHandlers({ env: process.env }));

export const GET = (request: Request) => auth().GET(request);
export const POST = (request: Request) => auth().POST(request);
