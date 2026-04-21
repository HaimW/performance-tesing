import os
import logging
import socket
import urllib.parse
import urllib3
import yaml
import gevent
from locust import HttpUser, between, events
from locust.runners import MasterRunner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
with open(_cfg_path) as _f:
    _cfg = yaml.safe_load(_f)

_target = _cfg["target"]
_scenarios = _cfg["scenarios"]
_kpi = _cfg["kpi"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
_log = logging.getLogger("locust.kpi")

# DNS override: redirect the target domain to the origin IP so TCP bypasses the
# CDN while SNI still carries the real domain name (TLS cert validates normally).
_origin_ip = _target.get("origin_ip")
if _origin_ip:
    _target_host = urllib.parse.urlparse(_target["url"]).hostname
    _orig_create_connection = urllib3.util.connection.create_connection

    def _patched_create_connection(address, *args, **kwargs):
        host, port = address
        if host == _target_host:
            host = _origin_ip
        return _orig_create_connection((host, port), *args, **kwargs)

    urllib3.util.connection.create_connection = _patched_create_connection
    _log.info("DNS override active: %s → %s", _target_host, _origin_ip)


def _make_task(endpoint):
    method = endpoint["method"].lower()
    path = endpoint["path"]
    name = endpoint["name"]
    expected = endpoint.get("expected_status", 200)
    if isinstance(expected, int):
        expected = [expected]
    body = endpoint.get("body")

    def _task(self):
        kwargs = {"name": name, "catch_response": True, "allow_redirects": False}
        if method == "post" and body:
            kwargs["json"] = body
        with getattr(self.client, method)(path, **kwargs) as resp:
            if resp.status_code not in expected:
                resp.failure(f"{name} got {resp.status_code}")

    _task.__name__ = name.replace(" ", "_").replace("/", "_")
    return _task


# Build weighted task list: each endpoint repeated `weight` times
_task_list = []
for _ep in _scenarios["endpoints"]:
    _task_list.extend([_make_task(_ep)] * _ep["weight"])


class WebsiteUser(HttpUser):
    host = _target["url"]
    wait_time = between(_scenarios["think_time_min"], _scenarios["think_time_max"])
    tasks = _task_list


def _periodic_reporter(environment):
    interval = _kpi["report_interval"]
    while True:
        gevent.sleep(interval)
        stats = environment.runner.stats.total
        _log.info(
            "[KPI] users=%d | RPS=%.1f | RT_median=%.0fms | RT_p95=%.0fms | error_rate=%.2f%%",
            environment.runner.user_count,
            stats.current_rps,
            stats.get_response_time_percentile(0.50) or 0,
            stats.get_response_time_percentile(0.95) or 0,
            stats.fail_ratio * 100,
        )


@events.init.add_listener
def on_locust_init(environment, **kwargs):
    if isinstance(environment.runner, MasterRunner):
        gevent.spawn(_periodic_reporter, environment)
