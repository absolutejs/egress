import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  identity: {
    accent: "#ef4444",
    category: "security",
    description:
      "Deny-by-default outbound networking for AI agents with host, method, port, DNS/IP, redirect, credential, byte-limit, pinned-transport, and audit enforcement.",
    docsUrl: "https://github.com/absolutejs/egress",
    name: "@absolutejs/egress",
    tagline: "Give agents network access without giving them the network.",
  },
  settings: Type.Object({}),
  wiring: [],
});
