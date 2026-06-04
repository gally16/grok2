"""Subscription-driven proxy pool: pull Clash subscriptions, drive a mihomo
sidecar, and expose each upstream node as a local SOCKS port.

Pipeline (leader worker only):
    fetch subscription(s) → parse proxies → generate mihomo config with one
    SOCKS listener per node → write config → reload mihomo via its RESTful API
    → persist the node→port pool to ``data/proxy_pool.json``.

All workers read the pool file (via ProxyDirectory) to route requests; only the
leader runs this manager. mihomo itself is a sidecar container managed by Docker
(see docker-compose), not an in-process subprocess.
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from urllib.parse import quote

import aiohttp
import orjson
import yaml

from app.platform.config.snapshot import get_config
from app.platform.logging.logger import logger
from app.platform.paths import data_path
from app.platform.runtime.clock import now_ms

# Clash clients send this UA; some airports gate the subscription on it.
_SUB_UA = "clash-verge/v2.0.0"
_FETCH_TIMEOUT = 30

# Authenticated grok probe used by verify_with_grok mode. The rate-limits API
# is a *read* (does not consume the account's chat quota) yet traverses the full
# statsig-signed + Cloudflare path, so a风控'd egress IP shows up as 403/challenge.
_GROK_PROBE_URL = "https://grok.com/rest/rate-limits"
_GROK_PROBE_PAYLOAD = orjson.dumps({"modelName": "fast"})

# mihomo proxy-group name for the shared signer egress (see build_mihomo_config).
# Dashed + prefixed so it can't collide with a real subscription node name.
_SIGNER_GROUP = "GROK2API-AUTO"
# Health probe for that group. Deliberately grok.com (not a generic connectivity
# URL): these nodes often reach grok while gstatic/google is blocked, so the
# group health-checks against the only target that matters for the signer.
_SIGNER_PROBE_URL = "https://grok.com/"


@dataclass
class PoolNode:
    node_id: str
    name: str  # mihomo proxy name
    listener_port: int  # local SOCKS port mihomo exposes for this node
    proxy_url: str  # socks5://<host>:<port> consumed by the dataplane
    latency_ms: int | None = None  # measured delay; None = unreachable/untested
    healthy: bool = False  # reachable within timeout at last test


@dataclass
class PoolState:
    nodes: list[PoolNode] = field(default_factory=list)
    generated_at: int = 0
    source_count: int = 0  # how many subscription URLs contributed


# ---------------------------------------------------------------------------
# Pure helpers (no IO) — easy to unit-test / verify offline
# ---------------------------------------------------------------------------


def parse_clash_proxies(text: str) -> list[dict]:
    """Extract the ``proxies`` list from a Clash YAML document.

    Returns an empty list if the payload is not a mapping or has no proxies.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        logger.warning("subscription parse failed: error={}", exc)
        return []
    if not isinstance(doc, dict):
        return []
    proxies = doc.get("proxies")
    return (
        [p for p in proxies if isinstance(p, dict) and p.get("name")]
        if isinstance(proxies, list)
        else []
    )


def merge_proxies(groups: list[list[dict]]) -> list[dict]:
    """Merge proxies from multiple subscriptions, deduping by endpoint.

    Identity is ``(type, server, port)`` — the same upstream reached via two
    subscriptions counts once. Names are made unique with a numeric suffix so
    mihomo (which requires unique proxy names) never rejects the config.
    """
    seen_endpoints: set[tuple] = set()
    seen_names: set[str] = set()
    merged: list[dict] = []
    for group in groups:
        for p in group:
            endpoint = (p.get("type"), p.get("server"), p.get("port"))
            if endpoint in seen_endpoints:
                continue
            seen_endpoints.add(endpoint)
            node = dict(p)
            name = str(node["name"])
            if name in seen_names:
                i = 2
                while f"{name} #{i}" in seen_names:
                    i += 1
                name = f"{name} #{i}"
                node["name"] = name
            seen_names.add(name)
            merged.append(node)
    # Deterministic order by endpoint so the same node set always maps to the
    # same listener port across refreshes — a subscription that merely reorders
    # its entries must not shuffle port→upstream bindings (would break sticky IP).
    merged.sort(
        key=lambda p: (
            str(p.get("server")),
            str(p.get("port")),
            str(p.get("type")),
            str(p.get("name")),
        )
    )
    return merged


def build_mihomo_config(
    proxies: list[dict],
    *,
    listener_base_port: int,
    listen_host: str,
    controller_port: int,
    secret: str,
) -> tuple[dict, list[PoolNode]]:
    """Build a mihomo config exposing one SOCKS listener per node, plus a shared
    ``url-test`` group on the mixed-port for external consumers (e.g. the statsig
    signer) that have no access to the in-process node selection.

    Each per-node listener binds directly to its upstream via the ``proxy`` field
    (traffic on that port egresses through exactly that node). The mixed-port
    routes through a ``fallback`` group that probes grok.com and sticks to one
    grok-reachable node (switching only on failure), giving external clients the
    connection stability the signer needs. Returns ``(config_dict, pool_nodes)``.
    """
    listeners: list[dict] = []
    nodes: list[PoolNode] = []
    for idx, p in enumerate(proxies):
        port = listener_base_port + idx
        name = str(p["name"])
        listeners.append(
            {
                "name": f"in-{idx}",
                "type": "socks",
                "port": port,
                "listen": "0.0.0.0",
                "udp": False,
                "proxy": name,
            }
        )
        nodes.append(
            PoolNode(
                node_id=f"sub-{idx}",
                name=name,
                listener_port=port,
                proxy_url=f"socks5://{listen_host}:{port}",
            )
        )
    # Shared auto-select group for external consumers (signer) routed via the
    # mixed-port. Members = all nodes; mihomo's url-test picks the fastest
    # reachable one and re-checks lazily (only while the group sees traffic).
    # Guard the (near-impossible) name clash: proxies and groups share one name
    # map in mihomo, so a node named like the group would make the WHOLE config
    # unloadable — skip the group rather than write a dead config.
    proxy_names = [n.name for n in nodes]
    use_group = bool(proxy_names) and _SIGNER_GROUP not in proxy_names
    proxy_groups = (
        [
            {
                "name": _SIGNER_GROUP,
                # fallback (not url-test): stick to one reachable node and switch
                # ONLY on failure. url-test churns by latency, which severs the
                # signer's in-flight grok page load mid-handshake.
                "type": "fallback",
                "proxies": proxy_names,
                "url": _SIGNER_PROBE_URL,
                "interval": 300,
                # grok behind CF answers 200 (ok) or 403/503 (challenge / under
                # attack) — all mean the node reaches grok; the headless signer
                # clears the JS challenge itself. Accept them so fallback treats
                # the node as up and stays put. Connect failures/timeouts still
                # fail the probe and roll to the next node.
                "expected-status": "200/403/503",
                "lazy": True,
            }
        ]
        if use_group
        else []
    )
    config = {
        # mixed-port routes through the fallback group (see rules) — the single
        # egress that selection-unaware external clients (signer) can use.
        "mixed-port": listener_base_port - 1,
        "allow-lan": True,
        "bind-address": "*",
        "mode": "rule",
        "log-level": "warning",
        "external-controller": f"0.0.0.0:{controller_port}",
        "secret": secret,
        # Proxy-side DNS so targets resolve regardless of socks5 vs socks5h on
        # the client; a bare config without this fails with "dns resolve failed".
        # Plain directly-reachable resolvers — DoH/DoT endpoints may be blocked
        # from the sidecar's network, which would break every lookup.
        "dns": {
            "enable": True,
            "ipv6": False,
            "nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1"],
        },
        # No geoip/geosite rules are used (listeners bind directly), so skip the
        # MMDB auto-download that otherwise blocks first start behind a firewall.
        "geodata-mode": False,
        "proxies": proxies,
        "listeners": listeners,
        "proxy-groups": proxy_groups,
        "rules": [f"MATCH,{_SIGNER_GROUP}"] if use_group else ["MATCH,DIRECT"],
    }
    return config, nodes


# ---------------------------------------------------------------------------
# Manager (IO) — leader-only
# ---------------------------------------------------------------------------


class SubscriptionManager:
    """Owns the fetch→generate→reload→persist pipeline for subscription mode."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._probe_round = 0  # rotates the grok-verify token window across cycles

    # -- config accessors ---------------------------------------------------

    @staticmethod
    def _cfg():
        cfg = get_config()
        return {
            "urls": [
                u for u in cfg.get_list("proxy.subscription.urls", []) if str(u).strip()
            ],
            "api": cfg.get_str("proxy.subscription.mihomo_api", "http://mihomo:9090"),
            "secret": cfg.get_str("proxy.subscription.mihomo_secret", ""),
            "host": cfg.get_str("proxy.subscription.mihomo_host", "mihomo"),
            "base_port": cfg.get_int("proxy.subscription.listener_base_port", 7100),
            "controller_port": cfg.get_int(
                "proxy.subscription.mihomo_controller_port", 9090
            ),
            # path of the generated config as seen by the mihomo container
            "mihomo_config_path": cfg.get_str(
                "proxy.subscription.mihomo_config_path", "/data/mihomo.yaml"
            ),
            "test_url": cfg.get_str(
                "proxy.subscription.test_url", "http://www.gstatic.com/generate_204"
            ),
            "test_timeout_ms": cfg.get_int("proxy.subscription.test_timeout_ms", 5000),
            "verify_with_grok": cfg.get_bool(
                "proxy.subscription.verify_with_grok", False
            ),
            "grok_timeout_ms": cfg.get_int(
                "proxy.subscription.grok_test_timeout_ms", 12000
            ),
            "grok_concurrency": cfg.get_int(
                "proxy.subscription.grok_test_concurrency", 8
            ),
            "grok_tokens": cfg.get_int("proxy.subscription.grok_test_tokens", 4),
            "max_latency_ms": cfg.get_int("proxy.subscription.max_latency_ms", 0),
        }

    @staticmethod
    def _local_config_path() -> str:
        return str(data_path("mihomo.yaml"))

    @staticmethod
    def pool_path() -> str:
        return str(data_path("proxy_pool.json"))

    # -- pipeline -----------------------------------------------------------

    async def _fetch(self, url: str) -> str:
        timeout = aiohttp.ClientTimeout(total=_FETCH_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers={"User-Agent": _SUB_UA}) as resp:
                resp.raise_for_status()
                return await resp.text()

    async def refresh(self) -> PoolState | None:
        """Run the full pipeline once. Returns the new pool, or None on failure."""
        async with self._lock:
            cfg = self._cfg()
            if not cfg["urls"]:
                logger.warning(
                    "subscription refresh skipped: no proxy.subscription.urls configured"
                )
                return None

            groups: list[list[dict]] = []
            for url in cfg["urls"]:
                try:
                    text = await self._fetch(url)
                    parsed = parse_clash_proxies(text)
                    logger.info(
                        "subscription fetched: nodes={} url={}",
                        len(parsed),
                        _redact(url),
                    )
                    groups.append(parsed)
                except Exception as exc:
                    logger.warning(
                        "subscription fetch failed: url={} error={}", _redact(url), exc
                    )

            proxies = merge_proxies(groups)
            if not proxies:
                logger.warning("subscription refresh aborted: no usable nodes parsed")
                return None

            config, nodes = build_mihomo_config(
                proxies,
                listener_base_port=cfg["base_port"],
                listen_host=cfg["host"],
                controller_port=cfg["controller_port"],
                secret=cfg["secret"],
            )

            self._write_config(config)
            await self._reload_mihomo(
                cfg["api"], cfg["secret"], cfg["mihomo_config_path"]
            )
            await asyncio.sleep(2)  # let mihomo bring listeners/outbounds up

            await self._run_test(cfg, nodes)
            # Build-then-swap guard runs on the RAW (pre-cutoff) result: an
            # all-unhealthy measurement usually means the mihomo control plane or
            # test URL is transiently down, not that every upstream died.
            if sum(1 for n in nodes if n.healthy) == 0 and self._prev_healthy() > 0:
                logger.warning(
                    "subscription refresh produced 0 healthy nodes; keeping last-known-good pool"
                )
                return None
            # Cutoff is applied after the guard — filtering to 0 here is an
            # intentional config decision and is allowed to write through.
            self._apply_latency_cutoff(cfg, nodes)
            healthy = sum(1 for n in nodes if n.healthy)
            state = PoolState(
                nodes=nodes, generated_at=now_ms(), source_count=len(cfg["urls"])
            )
            self._write_pool(state)
            logger.info(
                "subscription pool refreshed: total={} healthy={} sources={}",
                len(nodes),
                healthy,
                len(cfg["urls"]),
            )
            return state

    async def retest(self) -> PoolState | None:
        """Re-measure latency of the existing pool without re-pulling the
        subscription or reloading mihomo. Cheaper than a full refresh."""
        async with self._lock:
            cfg = self._cfg()
            state = self._read_pool()
            if state is None or not state.nodes:
                return None
            prev_healthy = sum(1 for n in state.nodes if n.healthy)
            await self._run_test(cfg, state.nodes)
            # Guard on raw result (see refresh): transient probe failure → keep.
            if sum(1 for n in state.nodes if n.healthy) == 0 and prev_healthy > 0:
                logger.warning(
                    "subscription retest produced 0 healthy nodes; keeping last-known-good pool"
                )
                return None
            # Intentional cutoff applied after the guard.
            self._apply_latency_cutoff(cfg, state.nodes)
            healthy = sum(1 for n in state.nodes if n.healthy)
            state.generated_at = now_ms()
            self._write_pool(state)
            logger.info(
                "subscription pool retested: total={} healthy={}",
                len(state.nodes),
                healthy,
            )
            return state

    async def _test_nodes(self, cfg: dict, nodes: list[PoolNode]) -> None:
        """Measure each node's delay to the test URL via mihomo's control API,
        updating ``latency_ms``/``healthy`` in place. Runs concurrently."""
        api, secret = cfg["api"], cfg["secret"]
        test_url, timeout_ms = cfg["test_url"], cfg["test_timeout_ms"]
        headers = {"Authorization": f"Bearer {secret}"} if secret else {}
        sem = asyncio.Semaphore(20)
        client_timeout = aiohttp.ClientTimeout(total=timeout_ms / 1000 + 5)

        async with aiohttp.ClientSession(
            timeout=client_timeout, headers=headers
        ) as session:

            async def probe(node: PoolNode) -> None:
                url = (
                    f"{api.rstrip('/')}/proxies/{quote(node.name, safe='')}/delay"
                    f"?url={quote(test_url, safe='')}&timeout={timeout_ms}"
                )
                async with sem:
                    try:
                        async with session.get(url) as resp:
                            data = await resp.json()
                        delay = data.get("delay") if isinstance(data, dict) else None
                        if resp.status == 200 and isinstance(delay, int):
                            node.latency_ms, node.healthy = delay, True
                        else:
                            node.latency_ms, node.healthy = None, False
                    except Exception:
                        node.latency_ms, node.healthy = None, False

            await asyncio.gather(*(probe(n) for n in nodes))

    def pool_status(self) -> dict:
        """Read-only snapshot of the live pool for the admin UI: when it was last
        measured and how many nodes made it into the pool."""
        cfg = get_config()
        status = {
            "generated_at": 0,
            "total": 0,
            "healthy": 0,
            "verify_with_grok": cfg.get_bool(
                "proxy.subscription.verify_with_grok", False
            ),
            "max_latency_ms": cfg.get_int("proxy.subscription.max_latency_ms", 0),
        }
        state = self._read_pool()
        if state is None:
            return status
        healthy = [n for n in state.nodes if n.healthy]
        status.update(
            generated_at=state.generated_at,
            total=len(state.nodes),
            healthy=len(healthy),
        )
        return status

    async def _run_test(self, cfg: dict, nodes: list[PoolNode]) -> None:
        """Measure each node's latency + availability in place.

        With ``verify_with_grok`` on, probe via a real authenticated grok request
        (the accurate "can this IP serve grok" signal). Falls back to the cheap
        mihomo delay test when the toggle is off, or when no account tokens are
        available (inconclusive) — so we never end up with an empty pool.

        Measurement only — the ``max_latency_ms`` cutoff is applied by the caller
        AFTER the build-then-swap guard, so an intentional config filter to 0 is
        honored while a transient probe failure still keeps the last-known-good.
        """
        if not (cfg["verify_with_grok"] and await self._verify_with_grok(cfg, nodes)):
            await self._test_nodes(cfg, nodes)

    @staticmethod
    def _apply_latency_cutoff(cfg: dict, nodes: list[PoolNode]) -> None:
        """Hard ceiling: nodes slower than ``max_latency_ms`` never enter the
        pool (marked unhealthy). 0 disables the cutoff. Covers both grok-probe
        and delay latencies. Applied after the build-then-swap guard so it can
        legitimately filter the pool down to 0 (a config decision, not a fault)."""
        ceiling = cfg["max_latency_ms"]
        if ceiling <= 0:
            return
        dropped = 0
        for node in nodes:
            if (
                node.healthy
                and node.latency_ms is not None
                and node.latency_ms > ceiling
            ):
                node.healthy = False
                dropped += 1
        if dropped:
            logger.info(
                "subscription latency cutoff dropped {} node(s) over {}ms",
                dropped,
                ceiling,
            )

    async def _verify_with_grok(self, cfg: dict, nodes: list[PoolNode]) -> bool:
        """Probe every node with an authenticated grok request, updating
        ``latency_ms`` (probe round-trip) / ``healthy`` (HTTP 200) in place.

        Returns False (inconclusive) when no usable account tokens exist, OR when
        every node came back inconclusive (all sampled tokens turned out to be
        bad accounts) — so the caller falls back to the delay test instead of
        nuking the pool with an all-unhealthy result."""
        from app.dataplane.account import get_account_directory

        directory = await get_account_directory()
        # Rotate which active accounts probe this round so the same few tokens
        # aren't hammered across every node every cycle (429 / concentration risk).
        self._probe_round += 1
        tokens = directory.sample_active_tokens(
            limit=max(1, cfg["grok_tokens"]), offset=self._probe_round
        )
        if not tokens:
            logger.warning(
                "subscription grok-verify skipped: no active account tokens; "
                "falling back to delay test"
            )
            return False

        timeout_s = cfg["grok_timeout_ms"] / 1000
        sem = asyncio.Semaphore(max(1, cfg["grok_concurrency"]))

        async def probe(offset: int, node: PoolNode) -> bool:
            async with sem:
                return await self._probe_node_grok(node, tokens, offset, timeout_s)

        results = await asyncio.gather(*(probe(i, n) for i, n in enumerate(nodes)))
        # Not one node got a definitive answer → the sampled accounts are all bad,
        # not the nodes. Treat as inconclusive and fall back rather than writing an
        # empty pool (which build-then-swap would then keep stale forever).
        if not any(results):
            logger.warning(
                "subscription grok-verify inconclusive for all nodes (sampled "
                "accounts all invalid); falling back to delay test"
            )
            return False
        return True

    @staticmethod
    async def _probe_node_grok(
        node: PoolNode, tokens: list[str], offset: int, timeout_s: float
    ) -> bool:
        """Send a rate-limits probe through this node, rotating tokens on an
        account-level auth failure. Updates ``node.latency_ms`` / ``node.healthy``.

        Returns True when the probe was *conclusive* (a 200, or a definitive
        node/IP-level failure), False when inconclusive (every sampled token
        failed auth — an account problem, so the node's prior state is left as-is).

        Deliberately does NOT emit account/proxy feedback — this is a node test,
        not a user request, and must not pollute either state machine.

        Note: the lease carries only ``proxy_url`` (no per-node Cloudflare
        clearance bundle). For the common subscription deploy — mihomo SOCKS
        egress without per-node flaresolverr clearance — this matches what the
        real request path produces; deployments relying on per-node CF clearance
        could see a false-negative 403 here.
        """
        from app.control.proxy.models import ProxyLease
        from app.dataplane.reverse.protocol.xai_usage import (
            is_invalid_credentials_error,
        )
        from app.dataplane.reverse.transport.http import post_json

        lease = ProxyLease(lease_id=f"probe-{node.node_id}", proxy_url=node.proxy_url)
        n = len(tokens)
        for k in range(n):
            token = tokens[(offset + k) % n]
            t0 = now_ms()
            try:
                await post_json(
                    _GROK_PROBE_URL,
                    token,
                    _GROK_PROBE_PAYLOAD,
                    lease=lease,
                    timeout_s=timeout_s,
                )
                node.latency_ms, node.healthy = int(now_ms() - t0), True
                return True
            except Exception as exc:
                # Account-level auth failure (expired/blocked token, or a bare 401
                # with no recognizable body) → not the node's fault: next token.
                # A 403 without a credential marker stays node-fault below: for a
                # rotating-IP pool an unmarked 403 is far more likely a CF/IP block.
                status = getattr(exc, "status", None)
                if status == 401 or is_invalid_credentials_error(exc):
                    continue
                # 403 / 429 / 5xx / timeout / transport → this egress IP is unusable.
                node.latency_ms, node.healthy = None, False
                return True
        # Every sampled token failed auth → inconclusive; leave prior state intact.
        logger.debug(
            "subscription grok-probe inconclusive (all tokens failed auth): node={}",
            node.node_id,
        )
        return False

    def _write_config(self, config: dict) -> None:
        path = self._local_config_path()
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
        os.replace(tmp, path)

    def _write_pool(self, state: PoolState) -> None:
        path = self.pool_path()
        tmp = f"{path}.tmp"
        payload = {
            "generated_at": state.generated_at,
            "source_count": state.source_count,
            "nodes": [
                {
                    "node_id": n.node_id,
                    "name": n.name,
                    "listener_port": n.listener_port,
                    "proxy_url": n.proxy_url,
                    "latency_ms": n.latency_ms,
                    "healthy": n.healthy,
                }
                for n in state.nodes
            ],
        }
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        os.replace(tmp, path)

    def _prev_healthy(self) -> int:
        state = self._read_pool()
        return sum(1 for n in state.nodes if n.healthy) if state else 0

    def _read_pool(self) -> PoolState | None:
        path = self.pool_path()
        # os.replace makes writes atomic, so we never read a half-written file;
        # the broad except also shields readers (e.g. the admin status endpoint)
        # from a hand-edited or schema-incompatible pool file.
        try:
            with open(path, encoding="utf-8") as f:
                payload = json.load(f)
            nodes = [
                PoolNode(
                    node_id=n["node_id"],
                    name=n["name"],
                    listener_port=n["listener_port"],
                    proxy_url=n["proxy_url"],
                    latency_ms=n.get("latency_ms"),
                    healthy=bool(n.get("healthy", False)),
                )
                for n in payload.get("nodes", [])
            ]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return PoolState(
            nodes=nodes,
            generated_at=payload.get("generated_at", 0),
            source_count=payload.get("source_count", 0),
        )

    async def _reload_mihomo(self, api: str, secret: str, config_path: str) -> None:
        headers = {"Content-Type": "application/json"}
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        url = f"{api.rstrip('/')}/configs?force=true"
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.put(
                url, headers=headers, json={"path": config_path}
            ) as resp:
                if resp.status not in (200, 204):
                    body = (await resp.text())[:200]
                    raise RuntimeError(
                        f"mihomo reload failed: status={resp.status} body={body}"
                    )
        logger.info("mihomo config reloaded: path={}", config_path)


def _redact(url: str) -> str:
    """Trim a subscription URL for logging — keep host, drop the secret path."""
    try:
        from urllib.parse import urlparse

        u = urlparse(url)
        return f"{u.scheme}://{u.netloc}/…"
    except Exception:
        return "…"


_manager: SubscriptionManager | None = None


def get_subscription_manager() -> SubscriptionManager:
    global _manager
    if _manager is None:
        _manager = SubscriptionManager()
    return _manager


__all__ = [
    "PoolNode",
    "PoolState",
    "parse_clash_proxies",
    "merge_proxies",
    "build_mihomo_config",
    "SubscriptionManager",
    "get_subscription_manager",
]
