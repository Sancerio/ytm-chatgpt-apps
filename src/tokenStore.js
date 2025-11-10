class RestRedisTokenStore {
  constructor({ url, token, namespace = "ytm_tokens" }) {
    if (!url || !token) {
      throw new Error("Redis REST url/token required");
    }
    this.url = url.replace(/\/$/, "");
    this.token = token;
    this.namespace = namespace;
  }

  key(userKey) {
    return `${this.namespace}:${userKey}`;
  }

  async run(command, ...args) {
    const encoded = [command.toUpperCase(), ...args.map(arg => encodeURIComponent(String(arg)))].join("/");
    const resp = await fetch(`${this.url}/${encoded}`, {
      headers: {
        Authorization: `Bearer ${this.token}`,
      },
    });
    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`[token-store] Redis request failed (${resp.status}): ${body}`);
    }
    let data;
    try {
      data = await resp.json();
    } catch (err) {
      throw new Error(`[token-store] Failed to parse Redis response: ${err.message}`);
    }
    if (data.error) {
      throw new Error(`[token-store] Redis error: ${data.error}`);
    }
    return data.result;
  }

  async get(userKey) {
    const raw = await this.run("get", this.key(userKey));
    if (typeof raw !== "string") return raw ?? null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async set(userKey, value) {
    const payload = JSON.stringify(value);
    await this.run("set", this.key(userKey), payload);
  }

  async delete(userKey) {
    await this.run("del", this.key(userKey));
  }
}

export function createTokenStore(redisConfig) {
  return new RestRedisTokenStore(redisConfig);
}

export { RestRedisTokenStore };
