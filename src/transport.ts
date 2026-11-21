import { isIP } from "node:net";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
/** Stable policy rules for diagnostics; never returns the supplied address. */
export const networkAddressBlockReason = (
  input: string,
): string | undefined => {
  const value = input.toLowerCase().replace(/^\[|\]$/gu, "");
  if (isIP(value) === 4) {
    const [a = 0, b = 0, c = 0] = value.split(".").map(Number);
    if (a === 0) return "ipv4_this_network";
    if (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    )
      return "ipv4_private";
    if (a === 127) return "ipv4_loopback";
    if (a >= 224) return "ipv4_multicast_reserved";
    if (a === 100 && b >= 64 && b <= 127) return "ipv4_shared";
    if (a === 169 && b === 254) return "ipv4_link_local";
    // IANA reserves these /24s, not the entire public 192.0.0.0/16.
    // Keep the conservative protocol-assignment policy, including anycast exceptions.
    if (a === 192 && b === 0 && c === 0) return "ipv4_protocol_assignment";
    if (
      (a === 192 && b === 0 && c === 2) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113)
    )
      return "ipv4_documentation";
    if (a === 192 && b === 88 && c === 99) return "ipv4_transition";
    if (a === 198 && (b === 18 || b === 19)) return "ipv4_benchmark";
    return undefined;
  }
  if (isIP(value) !== 6) return "invalid_address";
  if (!/^[23]/u.test(value)) return "ipv6_non_global";
  const [first, second = "0"] = value.split(":");
  const prefix = parseInt(first!, 16),
    subnet = parseInt(second || "0", 16);
  if (prefix === 0x2002) return "ipv6_transition";
  if (prefix === 0x2001 && subnet < 0x200) return "ipv6_special";
  if (
    (prefix === 0x2001 && subnet === 0xdb8) ||
    (prefix === 0x3fff && subnet < 0x1000)
  )
    return "ipv6_documentation";
  return undefined;
};
/** Shared conservative public-address classifier; caller retains destination policy. */
export const isPublicNetworkAddress = (input: string): boolean =>
  networkAddressBlockReason(input) === undefined;
export const pinnedPublicRequest = async (
  request: Request,
  options: {
    hostname: string;
    address: string;
    maxResponseBytes: number;
    /** Response headers are bounded independently of body bytes (default 64 KiB, maximum 1 MiB). */
    maxResponseHeaderBytes?: number;
    request?: typeof httpsRequest;
  },
): Promise<Response> => {
  request.signal.throwIfAborted();
  const url = new URL(request.url);
  if (
    !/^https?:$/u.test(url.protocol) ||
    !isPublicNetworkAddress(options.address)
  )
    throw new Error("Pinned destination must be public HTTP/HTTPS");
  const hostname = url.hostname.replace(/^\[|\]$/gu, "");
  if (
    hostname.toLowerCase() !==
      options.hostname.replace(/^\[|\]$/gu, "").toLowerCase() ||
    (isIP(hostname) && hostname !== options.address)
  )
    throw new Error("Pinned hostname does not match URL");
  if (
    !Number.isSafeInteger(options.maxResponseBytes) ||
    options.maxResponseBytes < 1
  )
    throw new Error("Positive response byte limit required");
  const maxHeaderSize = options.maxResponseHeaderBytes ?? 65_536;
  if (
    !Number.isSafeInteger(maxHeaderSize) ||
    maxHeaderSize < 1 ||
    maxHeaderSize > 1_048_576
  )
    throw new Error("Response header limit must be between 1 byte and 1 MiB");
  const body =
    request.method === "GET" || request.method === "HEAD"
      ? undefined
      : Buffer.from(await request.arrayBuffer());
  const requestImpl =
    options.request ?? (url.protocol === "https:" ? httpsRequest : httpRequest);
  return new Promise((resolve, reject) => {
    const outgoing = requestImpl(
      request.url,
      {
        agent: false,
        maxHeaderSize,
        headers: Object.fromEntries(request.headers),
        method: request.method,
        servername: isIP(options.hostname) ? undefined : options.hostname,
        lookup: (_name, lookupOptions, callback) => {
          const family = isIP(options.address) as 4 | 6;
          // Node/Bun connection racing requests the all-addresses lookup form.
          // Return only the already validated pin in either callback shape.
          if (lookupOptions.all)
            callback(null, [{ address: options.address, family }]);
          else callback(null, options.address, family);
        },
      },
      (incoming) => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        incoming.once("error", reject);
        incoming.on("data", (chunk: Buffer) => {
          bytes += chunk.byteLength;
          if (bytes > options.maxResponseBytes) {
            incoming.destroy(
              Object.assign(new Error("Response exceeds byte limit"), {
                code: "ERR_RESPONSE_BODY_TOO_LARGE",
              }),
            );
            return;
          }
          chunks.push(chunk);
        });
        incoming.once("end", () => {
          const headers = new Headers();
          for (let i = 0; i < incoming.rawHeaders.length; i += 2) {
            const name = incoming.rawHeaders[i],
              value = incoming.rawHeaders[i + 1];
            if (name !== undefined && value !== undefined)
              headers.append(name, value);
          }
          const status = incoming.statusCode ?? 502;
          try {
            resolve(
              new Response(
                request.method === "HEAD" || [204, 205, 304].includes(status)
                  ? null
                  : Buffer.concat(chunks),
                { headers, status },
              ),
            );
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    const abort = () =>
      outgoing.destroy(
        request.signal.reason instanceof Error
          ? request.signal.reason
          : new Error("Request aborted"),
      );
    if (request.signal.aborted) abort();
    else request.signal.addEventListener("abort", abort, { once: true });
    outgoing.once("close", () =>
      request.signal.removeEventListener("abort", abort),
    );
    outgoing.once("error", reject);
    outgoing.end(body);
  });
};
