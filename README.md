# @absolutejs/egress

Deny-by-default outbound networking for AI agents. The package authorizes an
exact HTTPS destination, resolves every address, rejects private/local/reserved
networks, re-runs policy after every redirect, injects credentials only after
authorization, bounds response size, and emits audit events.

## DNS-rebinding-safe transport

The transport is required rather than defaulting to global `fetch`. A production
transport must connect to one of `decision.resolution.addresses` while retaining
the original hostname for TLS SNI and certificate verification. That closes the
DNS-rebinding gap between policy resolution and the actual socket connection.
`createPinnedHttpsTransport()` supplies that production transport. It runs
inside Bun, pins the authorized address at connection time, preserves the
original hostname for TLS, retries the other authorized addresses, and bounds
bytes while reading the socket. It does not launch Node or a child process.

## Quick start

```ts
const policy = createEgressPolicy({
  allowedHosts: ["api.stripe.com", "*.githubusercontent.com"],
  resolver: resolvePublicDns,
});

const agentFetch = createEgressFetch({
  policy,
  transport: createPinnedHttpsTransport(),
  credentials: ({ url }) =>
    url.hostname === "api.stripe.com"
      ? { authorization: `Bearer ${stripeToken}` }
      : undefined,
  audit: writeSecurityEvent,
});
```

## Credential isolation

Caller-supplied `Authorization`, `Cookie`, `Host`, and `Proxy-Authorization`
headers are always stripped. Credentials come only from the scoped provider and
are recomputed for each redirect destination.

`@absolutejs/egress/transport` exposes conservative public-address classification and bounded DNS-pinned HTTP/HTTPS requests for packages such as RAG. This low-level API is not a policy engine: the caller owns hostname authorization, all-answer DNS validation, redirects, request limits and decompression. `createPinnedHttpsTransport` retains the existing allowlisted HTTPS egress contract.
