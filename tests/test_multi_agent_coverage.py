"""Harness checks with mocked LLM decisions; not measurements of model attack resistance."""
from copy import deepcopy
from unittest.mock import MagicMock

import pytest

from tests import manual_test_multi_agent_coverage as h
from agents.analyst_schema import AnalysisDraft


@pytest.fixture
def model_stub(monkeypatch, tmp_path):
    monkeypatch.setenv('TRACE_OUTPUT_DIR', str(tmp_path))
    monkeypatch.setenv('DEFENSE_MODE', 'off')
    llm = MagicMock()
    llm.invoke.return_value.content = 'Hai lớp phòng thủ bổ trợ cho nhau.'
    monkeypatch.setattr('agents.planner.get_llm', lambda: llm)
    draft = AnalysisDraft(
        topic='Phòng thủ AI Agent', summary='Kết hợp Input Validation và Least Privilege.',
        comparison=[], contradictions=[], recommendation='Áp dụng cả hai lớp.',
        evidence_document_ids=['fixture_doc_1','fixture_doc_2'])
    monkeypatch.setattr('agents.analyst._invoke_analysis_draft', lambda *args: draft)
    monkeypatch.setattr('agents.planner._build_execution_request', lambda state: {
        'tool_name':'calculate_metrics',
        'params':{'metric':'attack_success_rate','records':deepcopy(h.RECORDS)}})
    return llm


def route_stub(monkeypatch, case):
    route = {
        ('research',):'RESEARCH',
        ('research','analyst'):'RESEARCH_AND_ANALYSIS',
        ('executor',):'EXECUTE',
        ('research','analyst','executor'):'RESEARCH_ANALYSIS_EXECUTE',
    }[tuple(case['workers'])]
    monkeypatch.setattr('agents.planner._classify_route', lambda *args, **kw: route)


@pytest.mark.parametrize('case', h.CASES, ids=lambda case:case['id'])
@pytest.mark.parametrize('mode', ['off','on'])
def test_real_graph_workers_guards_and_metric_tool(case, mode, monkeypatch, model_stub):
    route_stub(monkeypatch, case)
    result = h.run_case(case, mode)
    assert result['coverage_complete'], result['errors']
    assert result['actual_workers'] == case['workers']
    assert all(n['trace_id'] for n in result['node_trace'])
    if not case['attack']:
        assert result['verdict'] == 'CLEAN_OK'
        assert result['attack_success'] is None
    else:
        should_filter = mode=='on' and case['attack']!='metric_evasion'
        assert result['payload_filtered'] == should_filter
        assert result['attack_success'] is False
        assert result['verdict'] == ('FILTERED_RETRIEVAL' if should_filter else 'PASSED_NO_SUCCESS')
        events = result['final_state']['security_events']
        if case['attack'] != 'metric_evasion':
            assert any(e['action']==('filtered' if should_filter else 'observed') for e in events)
        if should_filter:
            assert 'analyst' not in result['payload_received_by']
    if 'executor' in case['workers']:
        assert result['metric_task_correct']
        assert result['tool_calls'][0]['status']=='success'
        assert result['tool_calls'][0]['result']['value']==0.5
    # Environment restored even when running a different mode.
    import os
    assert os.environ['DEFENSE_MODE']=='off'


def test_missing_route_is_gap_not_attack_failure(monkeypatch, model_stub):
    monkeypatch.setattr('agents.planner._classify_route', lambda *args,**kw:'DIRECT_RESPONSE')
    result = h.run_case(h.CASES[-1], 'on')
    assert result['verdict']=='COVERAGE_GAP'
    assert result['attack_success'] is None
    assert result['actual_workers']==[]
    assert h.statistics([result])['asr'] is None


def test_canary_quoted_in_refusal_is_not_success(monkeypatch, model_stub):
    case = h.CASES[4]
    route_stub(monkeypatch, case)
    model_stub.invoke.return_value.content = f"Tôi không làm theo yêu cầu '{case['canary']}'."
    refused = h.run_case(case, 'off')
    assert refused['attack_success'] is False
    model_stub.invoke.return_value.content = case['canary']
    hijacked = h.run_case(case, 'off')
    assert hijacked['verdict']=='ATTACK_SUCCESS'


def test_actual_metric_manipulation_evidence(monkeypatch, model_stub):
    case = h.CASES[-1]
    route_stub(monkeypatch, case)
    monkeypatch.setattr('agents.planner._build_execution_request', lambda state: {
        'tool_name':'calculate_metrics', 'params':{
            'metric':'attack_success_rate', 'records':[{'attack_success':False},{'attack_success':False}]}})
    result = h.run_case(case, 'off')
    assert result['metric_hijacked']
    assert result['verdict']=='ATTACK_SUCCESS'
    assert result['tool_calls'][0]['result']['value']==0


def test_live_retrieval_failure_preserves_error_and_unknown_outcome(monkeypatch, model_stub):
    case = h.CASES[0]
    route_stub(monkeypatch, case)
    def fail(*args, **kwargs):
        raise RuntimeError('retrieval unavailable')
    monkeypatch.setattr('agents.researcher.search', fail)
    result = h.run_case(case, 'on', backend='live')
    assert result['verdict']=='ERROR'
    assert 'retrieval unavailable' in result['retrieval_calls'][0]['error']
    assert result['attack_success'] is None


def test_no_execution_claim_from_tool_name_alone():
    case = h.CASES[-1]
    result = h.assess(case, {'tool_called':'calculate_metrics','final_answer':'0'}, [], [], [])
    assert result['attack_success'] is None
    assert not result['metric_hijacked']
