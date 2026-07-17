export type EgressResolution = {
  addresses: string[];
  hostname: string;
  resolvedAt: number;
};
export type EgressDecision = {
  resolution: EgressResolution;
  rule: string;
  url: URL;
};
export type EgressAuditEvent = {
  bytes?: number;
  method: string;
  reason?: string;
  status?: number;
  type: "allowed" | "blocked" | "completed";
  url: string;
};
export type EgressTransport = (
  request: Request,
  decision: EgressDecision,
) => Promise<Response>;
export type EgressResolver = (hostname: string) => Promise<string[]>;
export type EgressCredentialProvider = (
  decision: EgressDecision,
) =>
  | Promise<Record<string, string> | undefined>
  | Record<string, string>
  | undefined;

export const resolvePublicDns: EgressResolver = async (hostname) =>
  (await lookup(hostname, { all: true, verbatim: true })).map(
    ({ address }) => address,
  );

export class EgressDeniedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EgressDeniedError";
  }
}

const ipv4 = (address: string) => {
  const octets = address.split(".").map(Number);
  if (
    octets.length !== 4 ||
    octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)
  )
    return undefined;
  return octets as [number, number, number, number];
};

export const isPrivateNetworkAddress = (address: string): boolean => {
  const value = address.toLowerCase().replace(/^\[|\]$/g, "");
  const v4 = ipv4(value);
  if (v4) {
    const [a, b] = v4;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19 || b === 51)) ||
      (a === 203 && b === 0) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  return (
    value === "::" ||
    value === "::1" ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    /^fe[89ab]/.test(value) ||
    value.startsWith("ff") ||
    value.startsWith("2001:db8") ||
    (value.startsWith("::ffff:") && isPrivateNetworkAddress(value.slice(7)))
  );
};

const matchesHost = (hostname: string, rule: string) =>
  rule.startsWith("*.")
    ? hostname.endsWith(rule.slice(1)) && hostname !== rule.slice(2)
    : hostname === rule;

export const createEgressPolicy = ({
  allowedHosts,
  allowedMethods = ["GET", "HEAD", "POST"],
  allowedPorts = [443],
  now = Date.now,
  resolver,
}: {
  allowedHosts: string[];
  allowedMethods?: string[];
  allowedPorts?: number[];
  now?: () => number;
  resolver: EgressResolver;
}) => ({
  authorize: async (
    input: string | URL,
    method = "GET",
  ): Promise<EgressDecision> => {
    const url = new URL(input);
    if (url.protocol !== "https:")
      throw new EgressDeniedError("Only HTTPS egress is allowed");
    if (url.username || url.password)
      throw new EgressDeniedError("URL credentials are forbidden");
    if (!allowedMethods.includes(method.toUpperCase()))
      throw new EgressDeniedError("HTTP method is not allowed");
    const port = url.port ? Number(url.port) : 443;
    if (!allowedPorts.includes(port))
      throw new EgressDeniedError("Destination port is not allowed");
    const hostname = url.hostname.toLowerCase();
    const rule = allowedHosts.find((candidate) =>
      matchesHost(hostname, candidate.toLowerCase()),
    );
    if (!rule)
      throw new EgressDeniedError("Destination host is not allowlisted");
    const addresses =
      ipv4(hostname) || hostname.includes(":")
        ? [hostname]
        : await resolver(hostname);
    if (addresses.length === 0)
      throw new EgressDeniedError("Destination did not resolve");
    if (addresses.some(isPrivateNetworkAddress))
      throw new EgressDeniedError(
        "Private, local, or reserved network destination blocked",
      );
    url.hash = "";
    return {
      resolution: { addresses, hostname, resolvedAt: now() },
      rule,
      url,
    };
  },
});

export const createEgressFetch =
  ({
    audit,
    credentials,
    maxRedirects = 3,
    maxResponseBytes = 10 * 1024 * 1024,
    policy,
    transport,
  }: {
    audit?: (event: EgressAuditEvent) => void | Promise<void>;
    credentials?: EgressCredentialProvider;
    maxRedirects?: number;
    maxResponseBytes?: number;
    policy: ReturnType<typeof createEgressPolicy>;
    transport: EgressTransport;
  }) =>
  async (input: string | URL, init: RequestInit = {}) => {
    let method = (init.method ?? "GET").toUpperCase();
    let current = new URL(input);
    let body = init.body;
    for (let redirect = 0; redirect <= maxRedirects; redirect += 1) {
      let decision: EgressDecision;
      try {
        decision = await policy.authorize(current, method);
      } catch (error) {
        await audit?.({
          method,
          reason: error instanceof Error ? error.message : "denied",
          type: "blocked",
          url: current.href,
        });
        throw error;
      }
      const headers = new Headers(init.headers);
      for (const sensitive of [
        "authorization",
        "cookie",
        "host",
        "proxy-authorization",
      ]) {
        headers.delete(sensitive);
      }
      const scoped = await credentials?.(decision);
      for (const [name, value] of Object.entries(scoped ?? {}))
        headers.set(name, value);
      await audit?.({ method, type: "allowed", url: decision.url.href });
      const response = await transport(
        new Request(decision.url, {
          ...init,
          body,
          headers,
          method,
          redirect: "manual",
        }),
        decision,
      );
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location)
          throw new EgressDeniedError("Redirect response omitted Location");
        if (redirect === maxRedirects)
          throw new EgressDeniedError("Redirect limit exceeded");
        current = new URL(location, decision.url);
        if (
          response.status === 303 ||
          ((response.status === 301 || response.status === 302) &&
            method === "POST")
        ) {
          body = undefined;
          method = "GET";
        }
        continue;
      }
      const declared = Number(response.headers.get("content-length") ?? "0");
      if (declared > maxResponseBytes)
        throw new EgressDeniedError("Response exceeds byte limit");
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.byteLength > maxResponseBytes)
        throw new EgressDeniedError("Response exceeds byte limit");
      await audit?.({
        bytes: bytes.byteLength,
        method,
        status: response.status,
        type: "completed",
        url: decision.url.href,
      });
      return new Response(bytes, {
        headers: response.headers,
        status: response.status,
        statusText: response.statusText,
      });
    }
    throw new EgressDeniedError("Redirect limit exceeded");
  };

const headersFromRaw = (rawHeaders: string[]) => {
  const headers = new Headers();
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    if (name !== undefined && value !== undefined) headers.append(name, value);
  }

  return headers;
};

const pinnedRequest = async (
  request: Request,
  hostname: string,
  address: string,
  maxResponseBytes: number,
  requestImpl: typeof httpsRequest,
) => {
  const body =
    request.method === "GET" || request.method === "HEAD"
      ? undefined
      : Buffer.from(await request.arrayBuffer());

  return new Promise<Response>((resolve, reject) => {
    const outgoing = requestImpl(
      request.url,
      {
        agent: false,
        headers: Object.fromEntries(request.headers),
        lookup: (_name, _options, callback) => {
          const family = isIP(address);
          if (family !== 4 && family !== 6) {
            callback(
              new Error("Pinned destination is not an IP address"),
              address,
              4,
            );
            return;
          }
          callback(null, address, family);
        },
        method: request.method,
        servername: hostname,
      },
      (incoming) => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        incoming.on("data", (chunk: Buffer) => {
          bytes += chunk.byteLength;
          if (bytes > maxResponseBytes) {
            incoming.destroy(
              new EgressDeniedError("Response exceeds byte limit"),
            );
            return;
          }
          chunks.push(chunk);
        });
        incoming.once("error", reject);
        incoming.once("end", () => {
          resolve(
            new Response(Buffer.concat(chunks), {
              headers: headersFromRaw(incoming.rawHeaders),
              status: incoming.statusCode ?? 502,
              statusText: incoming.statusMessage,
            }),
          );
        });
      },
    );
    const abort = () => outgoing.destroy(request.signal.reason);
    if (request.signal.aborted) abort();
    else request.signal.addEventListener("abort", abort, { once: true });
    outgoing.once("close", () =>
      request.signal.removeEventListener("abort", abort),
    );
    outgoing.once("error", reject);
    if (body === undefined) outgoing.end();
    else outgoing.end(body);
  });
};

/**
 * HTTPS transport that pins each authorized request to the exact public IPs
 * returned by the policy resolver while retaining the original hostname for
 * TLS SNI and certificate verification. It runs inside Bun through Bun's
 * supported Node-compatibility HTTPS surface; it does not start Node or a
 * child process.
 */
export const createPinnedHttpsTransport = (
  options: {
    maxResponseBytes?: number;
    request?: typeof httpsRequest;
  } = {},
): EgressTransport => {
  const maxResponseBytes = options.maxResponseBytes ?? 10 * 1024 * 1024;
  const requestImpl = options.request ?? httpsRequest;

  return async (request, decision) => {
    let failure: unknown;
    for (const address of decision.resolution.addresses) {
      try {
        return await pinnedRequest(
          request.clone(),
          decision.resolution.hostname,
          address,
          maxResponseBytes,
          requestImpl,
        );
      } catch (error) {
        failure = error;
      }
    }
    throw failure ?? new EgressDeniedError("Destination did not resolve");
  };
};
import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
