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
