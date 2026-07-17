import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import type { IncomingMessage } from "node:http";
import type { request as httpsRequest, RequestOptions } from "node:https";
import { describe, expect, test } from "bun:test";
import {
  createEgressFetch,
  createEgressPolicy,
  createPinnedHttpsTransport,
  EgressDeniedError,
  isPrivateNetworkAddress,
  type EgressTransport,
} from "../src";

test("pinned transport connects to an authorized address with original TLS identity", async () => {
  let pinnedAddress = "";
  let servername = "";
  const request = ((
    _url: string,
    options: RequestOptions,
    handle: (response: IncomingMessage) => void,
  ) => {
    servername = String(options.servername);
    const outgoing = new EventEmitter() as EventEmitter & {
      destroy: (error?: Error) => void;
      end: (body?: unknown) => void;
    };
    outgoing.destroy = (error) => {
      if (error) outgoing.emit("error", error);
    };
    outgoing.end = () => {
      const pinnedLookup = options.lookup as (
        hostname: string,
        lookupOptions: object,
        callback: (
          error: Error | null,
          address: string,
          family: number,
        ) => void,
      ) => void;
      pinnedLookup("api.example.com", {}, (error, address) => {
        if (error) {
          outgoing.emit("error", error);
          return;
        }
        pinnedAddress = address;
        const incoming = new PassThrough() as PassThrough & IncomingMessage;
        Object.assign(incoming, {
          rawHeaders: ["content-type", "text/plain"],
          statusCode: 200,
          statusMessage: "OK",
        });
        handle(incoming);
        incoming.end("pinned");
      });
    };

    return outgoing;
  }) as unknown as typeof httpsRequest;
  const transport = createPinnedHttpsTransport({ request });
  const response = await transport(new Request("https://api.example.com/v1"), {
    resolution: {
      addresses: ["93.184.216.34"],
      hostname: "api.example.com",
      resolvedAt: 1,
    },
    rule: "api.example.com",
    url: new URL("https://api.example.com/v1"),
  });

  expect(await response.text()).toBe("pinned");
  expect(pinnedAddress).toBe("93.184.216.34");
  expect(servername).toBe("api.example.com");
});

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
