import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { mkdir } from "node:fs/promises";
import { chromium, type Browser, type Page } from "@playwright/test";

const DEFAULT_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

type ExitRecord = Readonly<{
  code: number | null;
  signal: NodeJS.Signals | null;
}>;

export type ManagedChrome = Readonly<{
  mainPid: number;
  page: Page;
  kill: () => Promise<ExitRecord>;
  close: () => Promise<void>;
}>;

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("web.remote.test.cdp_port_invalid");
  }
  const port = address.port;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
  return port;
}

function waitForExit(child: ChildProcess): Promise<ExitRecord> {
  return new Promise((resolve) => {
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, code: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(code)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  });
}

async function waitForCdp(port: number, childExit: Promise<ExitRecord>): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const ready = await Promise.race([
      fetch(`http://127.0.0.1:${port}/json/version`)
        .then((response) => response.ok)
        .catch(() => false),
      childExit.then((record) => {
        throw new Error(`web.remote.test.chrome_exited:${record.code}:${record.signal}`);
      }),
    ]);
    if (ready) {
      return;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("web.remote.test.chrome_cdp_timeout");
}

function killProcessGroup(mainPid: number, signal: NodeJS.Signals): void {
  try {
    process.kill(-mainPid, signal);
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ESRCH")) {
      throw error;
    }
  }
}

export async function launchManagedChrome(
  userDataDir: string,
  spkiPin: string,
): Promise<ManagedChrome> {
  await mkdir(userDataDir, { recursive: true, mode: 0o700 });
  const port = await reservePort();
  const executable = process.env.AGENTDECK_W3_CHROME_EXECUTABLE ?? DEFAULT_CHROME;
  const child = spawn(
    executable,
    [
      "--headless=new",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      `--ignore-certificate-errors-spki-list=${spkiPin}`,
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${userDataDir}`,
      "about:blank",
    ],
    { detached: true, stdio: "ignore" },
  );
  if (child.pid === undefined) {
    throw new Error("web.remote.test.chrome_pid_missing");
  }
  const mainPid = child.pid;
  const exited = waitForExit(child);
  try {
    await waitForCdp(port, exited);
    const browser: Browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
    const context = browser.contexts()[0];
    if (context === undefined) {
      throw new Error("web.remote.test.chrome_context_missing");
    }
    const page = context.pages()[0] ?? (await context.newPage());
    let terminal = false;
    return {
      mainPid,
      page,
      async kill() {
        if (terminal) {
          throw new Error("web.remote.test.chrome_already_terminal");
        }
        terminal = true;
        killProcessGroup(mainPid, "SIGKILL");
        const record = await withTimeout(exited, 10_000, "web.remote.test.chrome_kill_timeout");
        await browser.close().catch(() => undefined);
        return record;
      },
      async close() {
        if (terminal) {
          return;
        }
        terminal = true;
        await browser.close().catch(() => undefined);
        try {
          await withTimeout(exited, 5_000, "web.remote.test.chrome_close_timeout");
        } catch {
          killProcessGroup(mainPid, "SIGKILL");
          await withTimeout(exited, 10_000, "web.remote.test.chrome_kill_timeout");
        }
      },
    };
  } catch (error) {
    killProcessGroup(mainPid, "SIGKILL");
    await exited.catch(() => undefined);
    throw error;
  }
}
