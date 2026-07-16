# @absolutejs/egress

Deny-by-default outbound networking for AI agents. The package authorizes an
exact HTTPS destination, resolves every address, rejects private/local/reserved
networks, re-runs policy after every redirect, injects credentials only after
authorization, bounds response size, and emits audit events.

The transport is required rather than defaulting to global `fetch`. A production
transport must connect to one of `decision.resolution.addresses` while retaining
the original hostname for TLS SNI and certificate verification. That closes the
DNS-rebinding gap between policy resolution and the actual socket connection.

```ts
const policy = createEgressPolicy({
  allowedHosts: ["api.stripe.com", "*.githubusercontent.com"],
  resolver: resolvePublicDns,
});

const agentFetch = createEgressFetch({
  policy,
  transport: pinnedHttpsTransport,
  credentials: ({ url }) =>
    url.hostname === "api.stripe.com"
      ? { authorization: `Bearer ${stripeToken}` }
      : undefined,
  audit: writeSecurityEvent,
});
```

Caller-supplied `Authorization`, `Cookie`, `Host`, and `Proxy-Authorization`
headers are always stripped. Credentials come only from the scoped provider and
are recomputed for each redirect destination.
