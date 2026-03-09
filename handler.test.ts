import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  isPrivateIp,
  validateUrl,
  normalizeIpv4,
  sanitizeError,
  stripDangerousKeys,
  safeJsonParse,
  createDominusNodeFunctionHandler,
  type DominusNodeFunctionConfig,
} from "./handler.js";

// =========================================================================
// SSRF Protection — isPrivateIp
// =========================================================================

describe("isPrivateIp", () => {
  // IPv4 private ranges
  it("detects 127.0.0.1 as private", () => {
    expect(isPrivateIp("127.0.0.1")).toBe(true);
  });

  it("detects 127.255.255.255 as private", () => {
    expect(isPrivateIp("127.255.255.255")).toBe(true);
  });

  it("detects 10.0.0.0 as private", () => {
    expect(isPrivateIp("10.0.0.0")).toBe(true);
  });

  it("detects 10.255.255.255 as private", () => {
    expect(isPrivateIp("10.255.255.255")).toBe(true);
  });

  it("detects 172.16.0.1 as private", () => {
    expect(isPrivateIp("172.16.0.1")).toBe(true);
  });

  it("detects 172.31.255.255 as private", () => {
    expect(isPrivateIp("172.31.255.255")).toBe(true);
  });

  it("allows 172.15.0.1 (not private)", () => {
    expect(isPrivateIp("172.15.0.1")).toBe(false);
  });

  it("allows 172.32.0.1 (not private)", () => {
    expect(isPrivateIp("172.32.0.1")).toBe(false);
  });

  it("detects 192.168.0.1 as private", () => {
    expect(isPrivateIp("192.168.0.1")).toBe(true);
  });

  it("detects 169.254.169.254 (link-local) as private", () => {
    expect(isPrivateIp("169.254.169.254")).toBe(true);
  });

  it("detects 0.0.0.0 as private", () => {
    expect(isPrivateIp("0.0.0.0")).toBe(true);
  });

  // CGNAT
  it("detects 100.64.0.1 (CGNAT) as private", () => {
    expect(isPrivateIp("100.64.0.1")).toBe(true);
  });

  it("detects 100.127.255.255 (CGNAT upper) as private", () => {
    expect(isPrivateIp("100.127.255.255")).toBe(true);
  });

  it("allows 100.63.255.255 (below CGNAT)", () => {
    expect(isPrivateIp("100.63.255.255")).toBe(false);
  });

  // Multicast
  it("detects 224.0.0.1 (multicast) as private", () => {
    expect(isPrivateIp("224.0.0.1")).toBe(true);
  });

  it("detects 255.255.255.255 (broadcast) as private", () => {
    expect(isPrivateIp("255.255.255.255")).toBe(true);
  });

  // Public IPs
  it("allows 8.8.8.8 (public)", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
  });

  it("allows 1.1.1.1 (public)", () => {
    expect(isPrivateIp("1.1.1.1")).toBe(false);
  });

  // IPv6
  it("detects ::1 as private", () => {
    expect(isPrivateIp("::1")).toBe(true);
  });

  it("detects :: as private", () => {
    expect(isPrivateIp("::")).toBe(true);
  });

  it("detects fc00::1 as private (ULA)", () => {
    expect(isPrivateIp("fc00::1")).toBe(true);
  });

  it("detects fd12::1 as private (ULA)", () => {
    expect(isPrivateIp("fd12::1")).toBe(true);
  });

  it("detects fe80::1 as private (link-local)", () => {
    expect(isPrivateIp("fe80::1")).toBe(true);
  });

  // IPv4-mapped IPv6
  it("detects ::ffff:127.0.0.1 as private", () => {
    expect(isPrivateIp("::ffff:127.0.0.1")).toBe(true);
  });

  it("detects ::ffff:10.0.0.1 as private", () => {
    expect(isPrivateIp("::ffff:10.0.0.1")).toBe(true);
  });

  it("detects ::ffff:7f00:0001 as private (hex form)", () => {
    expect(isPrivateIp("::ffff:7f00:0001")).toBe(true);
  });

  // Bracketed IPv6
  it("handles [::1] bracketed form", () => {
    expect(isPrivateIp("[::1]")).toBe(true);
  });

  // Zone ID
  it("strips IPv6 zone ID", () => {
    expect(isPrivateIp("fe80::1%eth0")).toBe(true);
  });
});

// =========================================================================
// SSRF Protection — normalizeIpv4
// =========================================================================

describe("normalizeIpv4", () => {
  it("normalizes decimal integer to dotted-decimal", () => {
    expect(normalizeIpv4("2130706433")).toBe("127.0.0.1");
  });

  it("normalizes hex to dotted-decimal", () => {
    expect(normalizeIpv4("0x7f000001")).toBe("127.0.0.1");
  });

  it("normalizes octal octets", () => {
    expect(normalizeIpv4("0177.0.0.1")).toBe("127.0.0.1");
  });

  it("normalizes mixed-radix", () => {
    expect(normalizeIpv4("0xC0.0xA8.0x01.0x01")).toBe("192.168.1.1");
  });

  it("returns null for hostnames", () => {
    expect(normalizeIpv4("example.com")).toBeNull();
  });

  it("handles 0", () => {
    expect(normalizeIpv4("0")).toBe("0.0.0.0");
  });

  it("handles max uint32", () => {
    expect(normalizeIpv4("4294967295")).toBe("255.255.255.255");
  });

  it("returns null for out-of-range", () => {
    expect(normalizeIpv4("4294967296")).toBeNull();
  });
});

// =========================================================================
// SSRF Protection — validateUrl
// =========================================================================

describe("validateUrl", () => {
  it("accepts valid https URL", () => {
    const parsed = validateUrl("https://httpbin.org/ip");
    expect(parsed.hostname).toBe("httpbin.org");
  });

  it("accepts valid http URL", () => {
    const parsed = validateUrl("http://example.com/path");
    expect(parsed.hostname).toBe("example.com");
  });

  it("rejects invalid URL", () => {
    expect(() => validateUrl("not-a-url")).toThrow(/Invalid URL/);
  });

  it("rejects file:// protocol", () => {
    expect(() => validateUrl("file:///etc/passwd")).toThrow(/protocols/);
  });

  it("rejects ftp:// protocol", () => {
    expect(() => validateUrl("ftp://ftp.example.com")).toThrow(/protocols/);
  });

  it("rejects localhost", () => {
    expect(() => validateUrl("http://localhost/secret")).toThrow(/localhost/);
  });

  it("rejects 0.0.0.0", () => {
    expect(() => validateUrl("http://0.0.0.0/")).toThrow(/localhost/);
  });

  it("rejects private IPs", () => {
    expect(() => validateUrl("http://192.168.1.1/admin")).toThrow(/private/i);
  });

  it("rejects .localhost TLD", () => {
    expect(() => validateUrl("http://evil.localhost/")).toThrow(/localhost/);
  });

  it("rejects .local hostname", () => {
    expect(() => validateUrl("http://printer.local/")).toThrow(/internal/);
  });

  it("rejects .internal hostname", () => {
    expect(() => validateUrl("http://db.internal/")).toThrow(/internal/);
  });

  it("rejects .arpa hostname", () => {
    expect(() => validateUrl("http://1.168.192.in-addr.arpa/")).toThrow(
      /internal/,
    );
  });

  it("rejects embedded credentials", () => {
    expect(() => validateUrl("http://user:pass@example.com/")).toThrow(
      /credentials/,
    );
  });

  it("rejects cloud metadata endpoint", () => {
    expect(() =>
      validateUrl("http://169.254.169.254/latest/meta-data/"),
    ).toThrow(/private/i);
  });

  it("rejects hex-encoded loopback", () => {
    expect(() => validateUrl("http://0x7f000001/")).toThrow(/private/i);
  });

  it("rejects decimal-encoded loopback", () => {
    expect(() => validateUrl("http://2130706433/")).toThrow(/private/i);
  });
});

// =========================================================================
// Credential Sanitization
// =========================================================================

describe("sanitizeError", () => {
  it("redacts dn_live_ tokens", () => {
    expect(sanitizeError("failed with dn_live_abc123key")).toBe(
      "failed with ***",
    );
  });

  it("redacts dn_test_ tokens", () => {
    expect(sanitizeError("error at dn_test_xyz789")).toBe("error at ***");
  });

  it("redacts multiple tokens", () => {
    const result = sanitizeError("keys: dn_live_a and dn_test_b");
    expect(result).not.toContain("dn_live_a");
    expect(result).not.toContain("dn_test_b");
  });

  it("leaves non-credential strings unchanged", () => {
    expect(sanitizeError("no secrets here")).toBe("no secrets here");
  });

  it("handles empty string", () => {
    expect(sanitizeError("")).toBe("");
  });
});

// =========================================================================
// Prototype Pollution Prevention
// =========================================================================

describe("stripDangerousKeys", () => {
  it("removes constructor key", () => {
    const obj: any = { constructor: "evil", a: 1 };
    stripDangerousKeys(obj);
    expect(Object.prototype.hasOwnProperty.call(obj, "constructor")).toBe(false);
    expect(obj.a).toBe(1);
  });

  it("removes prototype key", () => {
    const obj: any = { prototype: "evil", b: 2 };
    stripDangerousKeys(obj);
    expect(obj.prototype).toBeUndefined();
  });

  it("handles nested objects recursively", () => {
    const obj: any = { nested: { constructor: "bad", ok: true } };
    stripDangerousKeys(obj);
    expect(Object.prototype.hasOwnProperty.call(obj.nested, "constructor")).toBe(false);
    expect(obj.nested.ok).toBe(true);
  });

  it("handles arrays", () => {
    const arr: any[] = [{ constructor: "bad" }, { safe: true }];
    stripDangerousKeys(arr);
    expect(Object.prototype.hasOwnProperty.call(arr[0], "constructor")).toBe(false);
    expect(arr[1].safe).toBe(true);
  });

  it("handles null/undefined", () => {
    expect(() => stripDangerousKeys(null)).not.toThrow();
    expect(() => stripDangerousKeys(undefined)).not.toThrow();
  });

  it("handles primitives", () => {
    expect(() => stripDangerousKeys(42)).not.toThrow();
    expect(() => stripDangerousKeys("string")).not.toThrow();
  });

  it("stops at depth 50", () => {
    let obj: any = { safe: true };
    for (let i = 0; i < 60; i++) {
      obj = { child: obj };
    }
    expect(() => stripDangerousKeys(obj)).not.toThrow();
  });
});

describe("safeJsonParse", () => {
  it("parses valid JSON", () => {
    const result = safeJsonParse<{ a: number }>('{"a": 1}');
    expect(result.a).toBe(1);
  });

  it("strips dangerous keys from parsed JSON", () => {
    const result = safeJsonParse<any>('{"constructor": "evil", "a": 1}');
    expect(Object.prototype.hasOwnProperty.call(result, "constructor")).toBe(false);
    expect(result.a).toBe(1);
  });

  it("strips nested dangerous keys", () => {
    const result = safeJsonParse<any>(
      '{"nested": {"prototype": "bad", "ok": true}}',
    );
    expect(result.nested.prototype).toBeUndefined();
    expect(result.nested.ok).toBe(true);
  });

  it("throws on invalid JSON", () => {
    expect(() => safeJsonParse("not json")).toThrow();
  });
});

// =========================================================================
// Handler Factory
// =========================================================================

describe("createDominusNodeFunctionHandler", () => {
  it("throws on missing apiKey", () => {
    expect(() =>
      createDominusNodeFunctionHandler({ apiKey: "" }),
    ).toThrow(/apiKey is required/);
  });

  it("throws on non-string apiKey", () => {
    expect(() =>
      createDominusNodeFunctionHandler({ apiKey: null as any }),
    ).toThrow(/apiKey is required/);
  });

  it("returns a function", () => {
    const handler = createDominusNodeFunctionHandler({
      apiKey: "dn_test_abc123",
    });
    expect(typeof handler).toBe("function");
  });

  it("accepts custom baseUrl and timeoutMs", () => {
    const handler = createDominusNodeFunctionHandler({
      apiKey: "dn_test_abc123",
      baseUrl: "http://localhost:3000",
      timeoutMs: 5000,
    });
    expect(typeof handler).toBe("function");
  });
});

// =========================================================================
// Dispatch Table — handler dispatching
// =========================================================================

describe("handler dispatching", () => {
  let handler: (name: string, args: Record<string, unknown>) => Promise<string>;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    // Mock fetch for auth
    globalThis.fetch = vi.fn().mockImplementation((url: string, init?: any) => {
      if (typeof url === "string" && url.includes("/api/auth/verify-key")) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: () => Promise.resolve('{"token": "jwt-mock-token"}'),
          headers: new Headers({ "content-length": "30" }),
        });
      }
      // Default: mock API call success
      return Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve('{"success": true}'),
        headers: new Headers({ "content-length": "20" }),
      });
    });

    handler = createDominusNodeFunctionHandler({
      apiKey: "dn_test_abc123",
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns error for unknown function", async () => {
    const result = JSON.parse(await handler("unknown_function", {}));
    expect(result.error).toContain("Unknown function");
    expect(result.available).toBeDefined();
    expect(Array.isArray(result.available)).toBe(true);
  });

  it("dispatches dominusnode_check_balance", async () => {
    const result = await handler("dominusnode_check_balance", {});
    expect(JSON.parse(result)).toHaveProperty("success");
  });

  it("dispatches dominusnode_list_teams", async () => {
    const result = await handler("dominusnode_list_teams", {});
    expect(JSON.parse(result)).toHaveProperty("success");
  });

  it("dispatches dominusnode_list_agentic_wallets", async () => {
    const result = await handler("dominusnode_list_agentic_wallets", {});
    expect(JSON.parse(result)).toHaveProperty("success");
  });

  it("dispatches dominusnode_get_proxy_config", async () => {
    const result = await handler("dominusnode_get_proxy_config", {});
    expect(JSON.parse(result)).toHaveProperty("success");
  });

  it("dispatches dominusnode_list_sessions", async () => {
    const result = await handler("dominusnode_list_sessions", {});
    expect(JSON.parse(result)).toHaveProperty("success");
  });

  it("handler has all 53 functions", async () => {
    const result = JSON.parse(await handler("nonexistent", {}));
    expect(result.available).toHaveLength(53);
  });

  it("handler available list includes all expected names", async () => {
    const result = JSON.parse(await handler("nonexistent", {}));
    const expected = [
      // Proxy (3)
      "dominusnode_proxied_fetch",
      "dominusnode_get_proxy_config",
      "dominusnode_get_proxy_status",
      // Wallet (7)
      "dominusnode_check_balance",
      "dominusnode_get_transactions",
      "dominusnode_get_forecast",
      "dominusnode_check_payment",
      "dominusnode_topup_paypal",
      "dominusnode_topup_stripe",
      "dominusnode_topup_crypto",
      // Usage (3)
      "dominusnode_check_usage",
      "dominusnode_get_daily_usage",
      "dominusnode_get_top_hosts",
      // Sessions (1)
      "dominusnode_list_sessions",
      // Account lifecycle (6)
      "dominusnode_register",
      "dominusnode_login",
      "dominusnode_get_account_info",
      "dominusnode_verify_email",
      "dominusnode_resend_verification",
      "dominusnode_update_password",
      // API Keys (3)
      "dominusnode_list_keys",
      "dominusnode_create_key",
      "dominusnode_revoke_key",
      // Plans (3)
      "dominusnode_get_plan",
      "dominusnode_list_plans",
      "dominusnode_change_plan",
      // Agentic wallets (7)
      "dominusnode_create_agentic_wallet",
      "dominusnode_fund_agentic_wallet",
      "dominusnode_agentic_wallet_balance",
      "dominusnode_list_agentic_wallets",
      "dominusnode_agentic_transactions",
      "dominusnode_freeze_agentic_wallet",
      "dominusnode_unfreeze_agentic_wallet",
      "dominusnode_delete_agentic_wallet",
      "dominusnode_update_wallet_policy",
      // Teams (17)
      "dominusnode_create_team",
      "dominusnode_list_teams",
      "dominusnode_team_details",
      "dominusnode_team_fund",
      "dominusnode_team_create_key",
      "dominusnode_team_usage",
      "dominusnode_update_team",
      "dominusnode_update_team_member_role",
      "dominusnode_team_delete",
      "dominusnode_team_revoke_key",
      "dominusnode_team_list_keys",
      "dominusnode_team_list_members",
      "dominusnode_team_add_member",
      "dominusnode_team_remove_member",
      "dominusnode_team_invite_member",
      "dominusnode_team_list_invites",
      "dominusnode_team_cancel_invite",
      // x402 (1)
      "dominusnode_x402_info",
    ];
    for (const name of expected) {
      expect(result.available).toContain(name);
    }
  });
});

// =========================================================================
// Input Validation — per-handler
// =========================================================================

describe("handler input validation", () => {
  let handler: (name: string, args: Record<string, unknown>) => Promise<string>;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (typeof url === "string" && url.includes("/api/auth/verify-key")) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: () => Promise.resolve('{"token": "jwt-mock-token"}'),
          headers: new Headers({ "content-length": "30" }),
        });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve('{"success": true}'),
        headers: new Headers({ "content-length": "20" }),
      });
    });

    handler = createDominusNodeFunctionHandler({
      apiKey: "dn_test_abc123",
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // proxied_fetch
  it("proxied_fetch rejects missing url", async () => {
    const result = JSON.parse(
      await handler("dominusnode_proxied_fetch", {}),
    );
    expect(result.error).toContain("url");
  });

  it("proxied_fetch rejects localhost", async () => {
    const result = JSON.parse(
      await handler("dominusnode_proxied_fetch", {
        url: "http://localhost/secret",
      }),
    );
    expect(result.error).toContain("localhost");
  });

  it("proxied_fetch rejects private IP", async () => {
    const result = JSON.parse(
      await handler("dominusnode_proxied_fetch", {
        url: "http://192.168.1.1/admin",
      }),
    );
    expect(result.error).toMatch(/private/i);
  });

  it("proxied_fetch rejects OFAC country", async () => {
    const result = JSON.parse(
      await handler("dominusnode_proxied_fetch", {
        url: "https://example.com",
        country: "IR",
      }),
    );
    expect(result.error).toContain("OFAC");
  });

  it("proxied_fetch rejects POST method", async () => {
    const result = JSON.parse(
      await handler("dominusnode_proxied_fetch", {
        url: "https://example.com",
        method: "POST",
      }),
    );
    expect(result.error).toContain("not allowed");
  });

  it("proxied_fetch rejects DELETE method", async () => {
    const result = JSON.parse(
      await handler("dominusnode_proxied_fetch", {
        url: "https://example.com",
        method: "DELETE",
      }),
    );
    expect(result.error).toContain("not allowed");
  });

  // create_agentic_wallet
  it("create_agentic_wallet rejects missing label", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        spending_limit_cents: 100,
      }),
    );
    expect(result.error).toContain("label");
  });

  it("create_agentic_wallet rejects long label", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "a".repeat(101),
        spending_limit_cents: 100,
      }),
    );
    expect(result.error).toContain("100");
  });

  it("create_agentic_wallet rejects control chars in label", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "test\x00label",
        spending_limit_cents: 100,
      }),
    );
    expect(result.error).toContain("control characters");
  });

  it("create_agentic_wallet rejects invalid spending_limit_cents", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "test",
        spending_limit_cents: -5,
      }),
    );
    expect(result.error).toContain("spending_limit_cents");
  });

  // fund_agentic_wallet
  it("fund_agentic_wallet rejects missing wallet_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_fund_agentic_wallet", {
        amount_cents: 100,
      }),
    );
    expect(result.error).toContain("wallet_id");
  });

  it("fund_agentic_wallet rejects invalid amount", async () => {
    const result = JSON.parse(
      await handler("dominusnode_fund_agentic_wallet", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
        amount_cents: -5,
      }),
    );
    expect(result.error).toContain("amount_cents");
  });

  // agentic_wallet_balance
  it("agentic_wallet_balance rejects missing wallet_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_agentic_wallet_balance", {}),
    );
    expect(result.error).toContain("wallet_id");
  });

  // agentic_transactions
  it("agentic_transactions rejects missing wallet_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_agentic_transactions", {}),
    );
    expect(result.error).toContain("wallet_id");
  });

  it("agentic_transactions rejects invalid limit", async () => {
    const result = JSON.parse(
      await handler("dominusnode_agentic_transactions", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
        limit: 0,
      }),
    );
    expect(result.error).toContain("limit");
  });

  it("agentic_transactions rejects limit > 100", async () => {
    const result = JSON.parse(
      await handler("dominusnode_agentic_transactions", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
        limit: 101,
      }),
    );
    expect(result.error).toContain("limit");
  });

  // freeze_agentic_wallet
  it("freeze_agentic_wallet rejects missing wallet_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_freeze_agentic_wallet", {}),
    );
    expect(result.error).toContain("wallet_id");
  });

  // unfreeze_agentic_wallet
  it("unfreeze_agentic_wallet rejects missing wallet_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_unfreeze_agentic_wallet", {}),
    );
    expect(result.error).toContain("wallet_id");
  });

  // delete_agentic_wallet
  it("delete_agentic_wallet rejects missing wallet_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_delete_agentic_wallet", {}),
    );
    expect(result.error).toContain("wallet_id");
  });

  // create_team
  it("create_team rejects missing name", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_team", {}),
    );
    expect(result.error).toContain("name");
  });

  it("create_team rejects long name", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_team", {
        name: "a".repeat(101),
      }),
    );
    expect(result.error).toContain("100");
  });

  it("create_team rejects control chars in name", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_team", {
        name: "team\x07name",
      }),
    );
    expect(result.error).toContain("control characters");
  });

  it("create_team rejects invalid max_members", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_team", {
        name: "test",
        max_members: 101,
      }),
    );
    expect(result.error).toContain("max_members");
  });

  // team_details
  it("team_details rejects missing team_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_team_details", {}),
    );
    expect(result.error).toContain("team_id");
  });

  // team_fund
  it("team_fund rejects missing team_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_team_fund", { amount_cents: 100 }),
    );
    expect(result.error).toContain("team_id");
  });

  it("team_fund rejects amount below 100", async () => {
    const result = JSON.parse(
      await handler("dominusnode_team_fund", {
        team_id: "550e8400-e29b-41d4-a716-446655440000",
        amount_cents: 50,
      }),
    );
    expect(result.error).toContain("amount_cents");
  });

  it("team_fund rejects amount above 1000000", async () => {
    const result = JSON.parse(
      await handler("dominusnode_team_fund", {
        team_id: "550e8400-e29b-41d4-a716-446655440000",
        amount_cents: 1000001,
      }),
    );
    expect(result.error).toContain("amount_cents");
  });

  // team_create_key
  it("team_create_key rejects missing team_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_team_create_key", { label: "prod" }),
    );
    expect(result.error).toContain("team_id");
  });

  it("team_create_key rejects missing label", async () => {
    const result = JSON.parse(
      await handler("dominusnode_team_create_key", {
        team_id: "550e8400-e29b-41d4-a716-446655440000",
      }),
    );
    expect(result.error).toContain("label");
  });

  it("team_create_key rejects control chars in label", async () => {
    const result = JSON.parse(
      await handler("dominusnode_team_create_key", {
        team_id: "550e8400-e29b-41d4-a716-446655440000",
        label: "test\x01key",
      }),
    );
    expect(result.error).toContain("control characters");
  });

  // team_usage
  it("team_usage rejects missing team_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_team_usage", {}),
    );
    expect(result.error).toContain("team_id");
  });

  it("team_usage rejects invalid limit", async () => {
    const result = JSON.parse(
      await handler("dominusnode_team_usage", {
        team_id: "550e8400-e29b-41d4-a716-446655440000",
        limit: 0,
      }),
    );
    expect(result.error).toContain("limit");
  });

  // create_agentic_wallet with daily_limit_cents
  it("create_agentic_wallet accepts valid daily_limit_cents", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "test-bot",
        spending_limit_cents: 500,
        daily_limit_cents: 10000,
      }),
    );
    expect(result.success).toBe(true);
  });

  it("create_agentic_wallet rejects invalid daily_limit_cents", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "test-bot",
        spending_limit_cents: 500,
        daily_limit_cents: 0,
      }),
    );
    expect(result.error).toContain("daily_limit_cents");
  });

  it("create_agentic_wallet rejects daily_limit_cents > 1000000", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "test-bot",
        spending_limit_cents: 500,
        daily_limit_cents: 1000001,
      }),
    );
    expect(result.error).toContain("daily_limit_cents");
  });

  // create_agentic_wallet with allowed_domains
  it("create_agentic_wallet accepts valid allowed_domains", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "test-bot",
        spending_limit_cents: 500,
        allowed_domains: ["example.com", "api.github.com"],
      }),
    );
    expect(result.success).toBe(true);
  });

  it("create_agentic_wallet rejects non-array allowed_domains", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "test-bot",
        spending_limit_cents: 500,
        allowed_domains: "example.com",
      }),
    );
    expect(result.error).toContain("allowed_domains");
  });

  it("create_agentic_wallet rejects invalid domain format", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "test-bot",
        spending_limit_cents: 500,
        allowed_domains: ["-invalid.com"],
      }),
    );
    expect(result.error).toContain("Invalid domain format");
  });

  it("create_agentic_wallet rejects too many domains", async () => {
    const domains = Array.from({ length: 101 }, (_, i) => `d${i}.com`);
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "test-bot",
        spending_limit_cents: 500,
        allowed_domains: domains,
      }),
    );
    expect(result.error).toContain("100");
  });

  it("create_agentic_wallet rejects domain > 253 chars", async () => {
    const result = JSON.parse(
      await handler("dominusnode_create_agentic_wallet", {
        label: "test-bot",
        spending_limit_cents: 500,
        allowed_domains: ["a".repeat(254) + ".com"],
      }),
    );
    expect(result.error).toContain("253");
  });

  // update_wallet_policy
  it("update_wallet_policy dispatches with valid daily_limit_cents", async () => {
    const result = JSON.parse(
      await handler("dominusnode_update_wallet_policy", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
        daily_limit_cents: 5000,
      }),
    );
    expect(result.success).toBe(true);
  });

  it("update_wallet_policy dispatches with null daily_limit_cents", async () => {
    const result = JSON.parse(
      await handler("dominusnode_update_wallet_policy", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
        daily_limit_cents: null,
      }),
    );
    expect(result.success).toBe(true);
  });

  it("update_wallet_policy dispatches with valid allowed_domains", async () => {
    const result = JSON.parse(
      await handler("dominusnode_update_wallet_policy", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
        allowed_domains: ["example.com"],
      }),
    );
    expect(result.success).toBe(true);
  });

  it("update_wallet_policy dispatches with null allowed_domains", async () => {
    const result = JSON.parse(
      await handler("dominusnode_update_wallet_policy", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
        allowed_domains: null,
      }),
    );
    expect(result.success).toBe(true);
  });

  it("update_wallet_policy rejects missing wallet_id", async () => {
    const result = JSON.parse(
      await handler("dominusnode_update_wallet_policy", {
        daily_limit_cents: 5000,
      }),
    );
    expect(result.error).toContain("wallet_id");
  });

  it("update_wallet_policy rejects invalid UUID", async () => {
    const result = JSON.parse(
      await handler("dominusnode_update_wallet_policy", {
        wallet_id: "not-a-uuid",
        daily_limit_cents: 5000,
      }),
    );
    expect(result.error).toContain("UUID");
  });

  it("update_wallet_policy rejects invalid daily_limit_cents", async () => {
    const result = JSON.parse(
      await handler("dominusnode_update_wallet_policy", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
        daily_limit_cents: -1,
      }),
    );
    expect(result.error).toContain("daily_limit_cents");
  });

  it("update_wallet_policy rejects daily_limit_cents > 1000000", async () => {
    const result = JSON.parse(
      await handler("dominusnode_update_wallet_policy", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
        daily_limit_cents: 1000001,
      }),
    );
    expect(result.error).toContain("daily_limit_cents");
  });

  it("update_wallet_policy rejects invalid domain format", async () => {
    const result = JSON.parse(
      await handler("dominusnode_update_wallet_policy", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
        allowed_domains: ["..bad"],
      }),
    );
    expect(result.error).toContain("Invalid domain format");
  });

  it("update_wallet_policy rejects empty body (no fields)", async () => {
    const result = JSON.parse(
      await handler("dominusnode_update_wallet_policy", {
        wallet_id: "550e8400-e29b-41d4-a716-446655440000",
      }),
    );
    expect(result.error).toContain("At least one");
  });
});

// =========================================================================
// Error handling in dispatch
// =========================================================================

describe("handler error handling", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("scrubs credentials from API errors", async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (typeof url === "string" && url.includes("/api/auth/verify-key")) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: () => Promise.resolve('{"token": "jwt-mock-token"}'),
          headers: new Headers({ "content-length": "30" }),
        });
      }
      return Promise.resolve({
        ok: false,
        status: 500,
        text: () =>
          Promise.resolve(
            '{"error": "dn_live_secret123 failed"}',
          ),
        headers: new Headers({ "content-length": "50" }),
      });
    });

    const handler = createDominusNodeFunctionHandler({
      apiKey: "dn_test_abc123",
    });

    const result = JSON.parse(
      await handler("dominusnode_check_balance", {}),
    );
    expect(result.error).not.toContain("dn_live_secret123");
    expect(result.error).toContain("***");
  });
});
