import asyncio
import statistics
import time

from agents.pipeline import get_orchestrator
from api.models import AgentResult, NormalizedEvent


class MockAgent:
    """Lightweight agent used only for pipeline benchmarking."""

    def __init__(self, stage: str):
        self.stage = stage

    async def process_async(self, event: NormalizedEvent) -> AgentResult:
        await asyncio.sleep(0)

        return AgentResult(
            event_id=event.event_id,
            status="success",
            output={},
            timestamp="2026-10-07T12:00:00Z",
        )


def create_test_event() -> NormalizedEvent:
    return NormalizedEvent(
        event_id="benchmark-event-001",
        timestamp="2026-10-07T12:00:00Z",
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        flow_duration=1.5,
        total_fwd_packets=10,
        total_bwd_packets=8,
        total_length_fwd_packets=1000,
        total_length_bwd_packets=800,
        flow_bytes_per_sec=1200.0,
        flow_packets_per_sec=12.0,
        label="BENIGN",
        mitre_techniques=[],
        raw_payload={},
        source_dataset="benchmark",
    )


async def run_benchmark(iterations: int = 10):
    orchestrator = get_orchestrator()

    # Replace real agents with lightweight mock agents.
    for stage in [
        "triage",
        "correlation",
        "mitre",
        "enrichment",
        "investigation",
    ]:
        orchestrator.register_agent(stage, MockAgent(stage))

    # Report is optional and not included in this benchmark.
    orchestrator.register_agent("report", None)

    latencies = []

    # Warm-up run.
    await orchestrator.run_pipeline_async(create_test_event())

    for i in range(iterations):
        event = create_test_event()
        event.event_id = f"benchmark-event-{i + 1}"

        start = time.perf_counter()

        await orchestrator.run_pipeline_async(event)

        latency_ms = (time.perf_counter() - start) * 1000
        latencies.append(latency_ms)

    print("\n=== Pipeline Latency Benchmark ===")
    print(f"Iterations : {iterations}")
    print(f"Average    : {statistics.mean(latencies):.2f} ms")
    print(f"Minimum    : {min(latencies):.2f} ms")
    print(f"Maximum    : {max(latencies):.2f} ms")
    print(f"Median     : {statistics.median(latencies):.2f} ms")

    if len(latencies) >= 2:
        print(f"Std Dev    : {statistics.stdev(latencies):.2f} ms")


if __name__ == "__main__":
    asyncio.run(run_benchmark())