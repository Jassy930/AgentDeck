import { extname, resolve } from "node:path";

const webRoot = resolve(import.meta.dir, "..");
const distribution = resolve(webRoot, "dist");
const wasmOutput = resolve(webRoot, "generated/agentdeck-web-core");
const port = Number.parseInt(process.env.RELAY_WEB_TEST_PORT ?? "4173", 10);

function relayConnectSource(): string {
  const configured =
    process.env.AGENTDECK_WEB_WSS_ORIGIN ?? process.env.AGENTDECK_W1_WSS_ORIGIN;
  if (configured === undefined) {
    return "'self'";
  }
  const origin = new URL(configured);
  if (
    origin.protocol !== "wss:" ||
    origin.username !== "" ||
    origin.password !== "" ||
    origin.pathname !== "/" ||
    origin.search !== "" ||
    origin.hash !== "" ||
    origin.port === "0"
  ) {
    throw new Error("web.remote.server.origin_invalid");
  }
  return `'self' ${origin.origin}`;
}

const connectSource = relayConnectSource();

const securityHeaders = {
  "Cache-Control": "no-store",
  "Content-Security-Policy":
    `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src ${connectSource}; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'`,
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

const contentTypes: Readonly<Record<string, string>> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
};

function safeWasmPath(pathname: string): string | null {
  const match = /^\/wasm\/([a-zA-Z0-9_.-]+)$/u.exec(pathname);
  return match?.[1] === undefined ? null : resolve(wasmOutput, match[1]);
}

async function fileResponse(path: string): Promise<Response> {
  const file = Bun.file(path);
  if (!(await file.exists())) {
    return new Response("not found", { status: 404, headers: securityHeaders });
  }
  return new Response(file, {
    headers: {
      ...securityHeaders,
      "Content-Type": contentTypes[extname(path)] ?? "application/octet-stream",
    },
  });
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port,
  async fetch(request) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed", { status: 405, headers: securityHeaders });
    }
    const { pathname } = new URL(request.url);
    if (pathname === "/healthz") {
      return new Response("ok", { headers: { ...securityHeaders, "Content-Type": "text/plain" } });
    }
    if (pathname === "/favicon.ico") {
      return new Response(null, { status: 204, headers: securityHeaders });
    }
    if (pathname === "/") {
      return fileResponse(resolve(distribution, "index.html"));
    }
    if (["/main.js", "/main.js.map", "/styles.css", "/tokens.css"].includes(pathname)) {
      return fileResponse(resolve(distribution, pathname.slice(1)));
    }
    const wasmPath = safeWasmPath(pathname);
    if (wasmPath !== null) {
      return fileResponse(wasmPath);
    }
    return new Response("not found", { status: 404, headers: securityHeaders });
  },
});

console.log(`Relay Web Test Companion: ${server.url}`);
