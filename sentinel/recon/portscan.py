"""Port scanner with service detection."""
import asyncio
import socket

COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000, 22, 21, 25, 3306, 5432, 6379, 27017, 9200]

# Banner -> service hints
SERVICE_HINTS = {
    b"SSH": "ssh",
    b"HTTP": "http",
    b"220": "ftp/smtp",
    b"mysql": "mysql",
    b"redis": "redis",
}


class PortScanner:
    def __init__(self, max_concurrent: int = 50, timeout: float = 3.0):
        self.max_concurrent = max_concurrent
        self.timeout = timeout

    async def _scan_port(self, sem, host: str, port: int):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.timeout
                )
                # Try to grab banner
                banner = b""
                try:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                    banner = await asyncio.wait_for(reader.read(256), timeout=2)
                except Exception:
                    pass
                writer.close()
                service = ""
                for hint, name in SERVICE_HINTS.items():
                    if hint.lower() in banner.lower():
                        service = name
                        break
                is_web = port in (80, 443, 8080, 8443, 3000, 5000, 8000, 9000)
                from ..models import Asset
                return Asset(host=host, port=port, service=service,
                             banner=banner[:100].decode(errors="ignore"),
                             is_web=is_web)
            except Exception:
                return None

    async def scan(self, host: str, ports: list[int] = None) -> list:
        ports = ports or COMMON_PORTS
        sem = asyncio.Semaphore(self.max_concurrent)
        results = await asyncio.gather(*[
            self._scan_port(sem, host, p) for p in ports
        ])
        return [r for r in results if r]
