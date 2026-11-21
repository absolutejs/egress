import { expect, test } from "bun:test";
import { EventEmitter } from "node:events";
import type { request } from "node:https";
import { isPublicNetworkAddress, pinnedPublicRequest } from "../src/transport";
test("shared address classification rejects local, mapped and reserved IPv6 forms", () => {
  for (const ip of [
    "127.0.0.1",
    "100.64.0.1",
    "192.0.2.1",
    "198.51.100.2",
    "203.0.113.2",
    "::ffff:8.8.8.8",
    "2001:0000:1234::1",
    "2001:db8::1",
    "2002:808:808::",
    "3fff::1",
    "fc00::1",
  ])
    expect(isPublicNetworkAddress(ip)).toBe(false);
  for (const ip of [
    "8.8.8.8",
    "203.0.114.1",
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
  ])
    expect(isPublicNetworkAddress(ip)).toBe(true);
});
test("HTTP transport pins DNS, bounds bytes and validates hostname before sockets", async () => {
  let calls = 0;
  const fake = ((_url: unknown, options: any, callback: any) => {
    calls++;
    const outgoing = new EventEmitter() as any;
    outgoing.destroy = (error: Error) => {
      queueMicrotask(() => outgoing.emit("error", error));
      return outgoing;
    };
    outgoing.end = () =>
      queueMicrotask(() => {
        options.lookup("example.com", {}, (_err: unknown, address: string) =>
          expect(address).toBe("8.8.8.8"),
        );
        options.lookup(
          "example.com",
          { all: true },
          (error: unknown, addresses: unknown) => {
            expect(error).toBeNull();
            expect(addresses).toEqual([{ address: "8.8.8.8", family: 4 }]);
          },
        );
        const incoming = new EventEmitter() as any;
        incoming.rawHeaders = [];
        incoming.statusCode = 200;
        incoming.destroy = (error: Error) => incoming.emit("error", error);
        callback(incoming);
        incoming.emit("data", Buffer.from("12345"));
        incoming.emit("end");
        outgoing.emit("close");
      });
    return outgoing;
  }) as typeof request;
  await expect(
    pinnedPublicRequest(new Request("http://example.com"), {
      hostname: "example.com",
      address: "8.8.8.8",
      maxResponseBytes: 4,
      request: fake,
    }),
  ).rejects.toThrow("byte limit");
  const result = await pinnedPublicRequest(new Request("http://example.com"), {
    hostname: "example.com",
    address: "8.8.8.8",
    maxResponseBytes: 5,
    request: fake,
  });
  expect(await result.text()).toBe("12345");
  await expect(
    pinnedPublicRequest(new Request("http://127.0.0.1"), {
      hostname: "example.com",
      address: "8.8.8.8",
      maxResponseBytes: 5,
      request: fake,
    }),
  ).rejects.toThrow("hostname");
  expect(calls).toBe(2);
});

test("response headers have an explicit bounded allowance and reject invalid limits before sockets", async () => {
  let calls = 0;
  const fake = ((_url: unknown, options: any) => {
    calls++;
    expect(options.maxHeaderSize).toBe(65_536);
    expect(options.servername).toBe("example.com");
    expect(options.rejectUnauthorized).not.toBe(false);
    const outgoing = new EventEmitter() as any;
    outgoing.end = () =>
      queueMicrotask(() => {
        outgoing.emit(
          "error",
          Object.assign(new Error("overflow"), { code: "HPE_HEADER_OVERFLOW" }),
        );
        outgoing.emit("close");
      });
    return outgoing;
  }) as typeof request;
  const options = {
    hostname: "example.com",
    address: "8.8.8.8",
    maxResponseBytes: 100,
    request: fake,
  };
  await expect(
    pinnedPublicRequest(new Request("https://example.com"), options),
  ).rejects.toMatchObject({ code: "HPE_HEADER_OVERFLOW" });
  for (const maxResponseHeaderBytes of [0, -1, 1.5, Infinity, 1_048_577])
    await expect(
      pinnedPublicRequest(new Request("https://example.com"), {
        ...options,
        maxResponseHeaderBytes,
      }),
    ).rejects.toThrow("header limit");
  expect(calls).toBe(1);
});

test("real HTTP parser accepts normal large headers and rejects responses over the configured cap", async () => {
  const { createServer } = await import("node:http");
  const { request: requestImpl } = await import("node:http");
  const server = createServer((_req, res) => {
    res.setHeader("x-fixture", "a".repeat(18_000));
    res.end("readable evidence");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw Error("No test port");
  const local = ((_url: unknown, options: any, callback: any) =>
    requestImpl(
      { ...options, hostname: "127.0.0.1", port: address.port, path: "/" },
      callback,
    )) as typeof request;
  try {
    const options = {
      hostname: "example.com",
      address: "8.8.8.8",
      maxResponseBytes: 100,
      request: local,
    };
    expect(
      await (
        await pinnedPublicRequest(new Request("http://example.com"), options)
      ).text(),
    ).toBe("readable evidence");
    await expect(
      pinnedPublicRequest(new Request("http://example.com"), {
        ...options,
        maxResponseHeaderBytes: 16384,
      }),
    ).rejects.toMatchObject({ code: "HPE_HEADER_OVERFLOW" });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("public 192.0 neighbors remain usable while reserved /24 boundaries stay blocked", () => {
  for (const ip of [
    "192.0.1.0",
    "192.0.1.255",
    "192.0.3.0",
    "192.0.78.24",
    "192.0.78.25",
    "192.0.255.255",
  ])
    expect(isPublicNetworkAddress(ip)).toBe(true);
  for (const ip of [
    "192.0.0.0",
    "192.0.0.255",
    "192.0.2.0",
    "192.0.2.255",
    "192.168.0.1",
    "192.88.99.1",
  ])
    expect(isPublicNetworkAddress(ip)).toBe(false);
});
