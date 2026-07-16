import { describe, expect, test } from "bun:test";
import {
  createEgressFetch,
  createEgressPolicy,
  EgressDeniedError,
  isPrivateNetworkAddress,
  type EgressTransport,
} from "../src";

describe("egress policy", () => {
  test("blocks private, metadata, reserved, non-HTTPS, and non-allowlisted targets", async () => {
    expect(isPrivateNetworkAddress("127.0.0.1")).toBe(true);
    expect(isPrivateNetworkAddress("169.254.169.254")).toBe(true);
    expect(isPrivateNetworkAddress("::1")).toBe(true);
    const privatePolicy = createEgressPolicy({
      allowedHosts: ["api.example.com"],
      resolver: async () => ["10.0.0.1"],
    });
    await expect(
      privatePolicy.authorize("https://api.example.com"),
    ).rejects.toBeInstanceOf(EgressDeniedError);
    await expect(
      privatePolicy.authorize("http://api.example.com"),
    ).rejects.toThrow("HTTPS");
    await expect(
      privatePolicy.authorize("https://evil.example"),
    ).rejects.toThrow("allowlisted");
  });

  test("wildcards do not accidentally include the parent domain", async () => {
    const policy = createEgressPolicy({
      allowedHosts: ["*.example.com"],
      resolver: async () => ["93.184.216.34"],
    });
    expect((await policy.authorize("https://api.example.com")).rule).toBe(
      "*.example.com",
    );
    await expect(policy.authorize("https://example.com")).rejects.toThrow();
  });
});

test("redirects are reauthorized and credentials are scoped per hop", async () => {
  const seen: Array<{
    authorization: string | null;
    host: string;
    pinned: string[];
  }> = [];
  const transport: EgressTransport = async (request, decision) => {
    seen.push({
      authorization: request.headers.get("authorization"),
      host: new URL(request.url).hostname,
      pinned: decision.resolution.addresses,
    });
    return seen.length === 1
      ? new Response(null, {
          headers: { location: "https://cdn.example.net/file" },
          status: 302,
        })
      : new Response("safe");
  };
  const policy = createEgressPolicy({
    allowedHosts: ["api.example.com", "cdn.example.net"],
    resolver: async (hostname) => [
      hostname === "api.example.com" ? "93.184.216.34" : "93.184.216.35",
    ],
  });
  const secureFetch = createEgressFetch({
    credentials: ({ url }) =>
      url.hostname === "api.example.com"
        ? { authorization: "Bearer scoped" }
        : undefined,
    policy,
    transport,
  });
  expect(
    await (
      await secureFetch("https://api.example.com/start", {
        headers: { authorization: "Bearer attacker" },
      })
    ).text(),
  ).toBe("safe");
  expect(seen).toEqual([
    {
      authorization: "Bearer scoped",
      host: "api.example.com",
      pinned: ["93.184.216.34"],
    },
    { authorization: null, host: "cdn.example.net", pinned: ["93.184.216.35"] },
  ]);
});

test("enforces response byte limits even without Content-Length", async () => {
  const policy = createEgressPolicy({
    allowedHosts: ["api.example.com"],
    resolver: async () => ["93.184.216.34"],
  });
  const secureFetch = createEgressFetch({
    maxResponseBytes: 3,
    policy,
    transport: async () => new Response("four"),
  });
  await expect(secureFetch("https://api.example.com")).rejects.toThrow(
    "byte limit",
  );
});
