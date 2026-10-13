from agents.pipeline import get_orchestrator


def test_pipeline_registers_all_phase3_agents():
    orchestrator = get_orchestrator()

    assert "triage" in orchestrator._agents
    assert "correlation" in orchestrator._agents
    assert "mitre" in orchestrator._agents
    assert "enrichment" in orchestrator._agents
    assert "investigation" in orchestrator._agents


def test_report_agent_not_initialized_yet():
    orchestrator = get_orchestrator()

    assert "report" in orchestrator._agents
    assert orchestrator._agents["report"] is None


def test_get_orchestrator_returns_shared_instance():
    first = get_orchestrator()
    second = get_orchestrator()

    assert first is second