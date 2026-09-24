import { isIP } from "node:net";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
/** Shared conservative public-address classifier; caller retains destination policy. */
export const isPublicNetworkAddress = (input: string): boolean => {
  const value = input.toLowerCase().replace(/^\[|\]$/gu, "");
  if (isIP(value) === 4) {
    const [a = 0, b = 0, c = 0] = value.split(".").map(Number);
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)
    );
  }
  // Reject mapped, transition, local, multicast and documentation addresses.
  if (isIP(value) !== 6 || !/^[23]/u.test(value)) return false;
  const [first, second = "0"] = value.split(":");
  const prefix = parseInt(first!, 16),
    subnet = parseInt(second || "0", 16);
  return (
    prefix !== 0x2002 &&
    !(prefix === 0x2001 && (subnet < 0x200 || subnet === 0xdb8)) &&
    !(prefix === 0x3fff && subnet < 0x1000)
  );
};
export const pinnedPublicRequest = async (
  request: Request,
  options: {
    hostname: string;
    address: string;
    maxResponseBytes: number;
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
            incoming.destroy(new Error("Response exceeds byte limit"));
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
