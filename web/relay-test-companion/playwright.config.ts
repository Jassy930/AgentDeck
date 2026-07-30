import { defineConfig } from "@playwright/test";

const testSpkiPin =
  process.env.AGENTDECK_WEB_TEST_SPKI_PIN ?? process.env.AGENTDECK_W1_TEST_SPKI_PIN;
if (testSpkiPin !== undefined && !/^[A-Za-z0-9+/]{43}=$/u.test(testSpkiPin)) {
  throw new Error("web.remote.test_spki_pin_invalid");
}
const webPort = Number.parseInt(process.env.RELAY_WEB_TEST_PORT ?? "4173", 10);
if (!Number.isInteger(webPort) || webPort < 1 || webPort > 65_535) {
  throw new Error("web.remote.test_port_invalid");
}
const webOrigin = `http://127.0.0.1:${webPort}`;

export default defineConfig({
  testDir: "./tests/browser",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  outputDir: "test-results",
  reporter: [["line"]],
  use: {
    baseURL: webOrigin,
    browserName: "chromium",
    channel: "chrome",
    headless: true,
    launchOptions: {
      args:
        testSpkiPin === undefined
          ? []
          : [`--ignore-certificate-errors-spki-list=${testSpkiPin}`],
    },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  webServer: {
    command: "bun run serve:test",
    url: `${webOrigin}/healthz`,
    reuseExistingServer: false,
    timeout: 10_000,
  },
});
