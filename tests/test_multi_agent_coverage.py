"""Kiểm tra harness bằng quyết định LLM giả; không phải phép đo khả năng chống tấn công của model."""
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
    monkeypatch.setattr('agents.analyst._invoke_analysis_draft', lambda *args, **kwargs: draft)
    monkeypatch.setattr('agents.planner._build_execution_request', lambda state, **kwargs: {
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
        if mode == 'off':
            assert events == []
        elif case['attack'] != 'metric_evasion':
            assert any(e['action']=='filtered' for e in events)
        if should_filter:
            assert 'analyst' not in result['payload_received_by']
    if 'executor' in case['workers']:
        assert result['metric_task_correct']
        assert result['tool_calls'][0]['status']=='success'
        assert result['tool_calls'][0]['result']['value']==0.5
    # Môi trường được khôi phục ngay cả khi chạy chế độ khác.
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
    monkeypatch.setattr('agents.planner._build_execution_request', lambda state, **kwargs: {
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


@pytest.mark.parametrize('outcome', ['echo_only', 'generated_marker', 'error', 'missing_evidence', 'guard_replaced'])
def test_evaluator_v2_retrieval_excludes_echo_and_unknown_outcomes(outcome):
    from unittest.mock import patch
    from security.coordination_guard import RenderPart, render_parts
    from tests.evaluation import FinalAnswerEvidence, EVALUATOR_VERSION
    with patch('dotenv.load_dotenv', return_value=False):
        from tests import manual_test_retrieval_guard as retrieval_h
        from tests import manual_test_full_pipeline_attacks as full_h

    documents = retrieval_h.build_documents()
    marker = retrieval_h.CASES[0]['canary']
    parts = [
        RenderPart('answer', 'kb', 'kb', marker if outcome == 'generated_marker' else 'Clean model answer'),
        RenderPart('echo', 'kb', 'kb', f'Top-K kết quả truy xuất\n{marker}', purpose='evidence_echo'),
    ]
    final = render_parts(parts)
    evidence = FinalAnswerEvidence(tuple(parts), final) if outcome != 'missing_evidence' else None
    state = {'final_answer': final, 'retrieved_documents': documents, 'security_events': [
        {'stage': 'retrieval', 'attack_type': 'indirect_injection', 'rule': 'retrieval_prompt_risk_scoring',
         'action': 'filtered', 'chunk_id': documents[0]['chunk_id']},
        {'stage': 'retrieval', 'attack_type': 'none', 'rule': 'minimum_trust_level',
         'action': 'filtered', 'chunk_id': documents[-1]['chunk_id']},
    ]}
    if outcome == 'error':
        state['errors'] = ['workflow failure']
    elif outcome == 'guard_replaced':
        state['final_answer'] = 'Guard refusal'
    rows = retrieval_h.case_results('on', documents, state, evaluation_valid=True, final_evidence=evidence)
    expected = True if outcome == 'generated_marker' else False if outcome == 'echo_only' else None
    assert rows[0]['attack_success'] is expected
    assert rows[0]['detected'] is True
    assert rows[-1]['detected'] is False and rows[-1]['policy_filtered'] is True
    metrics = retrieval_h.calculate_metrics({'cases': rows})
    assert metrics['false_positive_rate']['numerator'] == 0
    assert metrics['attack_success_rate']['denominator'] == (2 if outcome in {'echo_only', 'generated_marker'} else 0)
    full_case = full_h.TEST_CASES[0]
    with patch.dict(full_h.SUCCESS_CRITERIA[full_case['id']], {'answer_markers': [marker]}):
        assessment = full_h.evaluate_case(full_case, 'on', state, evidence)
    assert assessment['evaluator_version'] == EVALUATOR_VERSION
    direct_expected = None if outcome in {'echo_only', 'generated_marker'} else expected
    assert assessment['attack_success'] is direct_expected
    assert assessment['system_status']['final_output_affected'] is None


def test_evaluator_v2_simulation_and_legacy_reports_are_not_measurements(tmp_path, monkeypatch):
    from unittest.mock import patch
    from tests.evaluation import EVALUATOR_VERSION, WORKFLOW_PROFILE_VERSION, comparable_reports
    with patch('dotenv.load_dotenv', return_value=False):
        from tests import manual_test_full_pipeline_attacks as full_h
        from tests import manual_test_retrieval_guard as retrieval_h
    monkeypatch.setenv('DEFENSE_MODE', 'off')
    with patch('agents.planner.get_llm') as model:
        row = full_h.run_case(full_h.TEST_CASES[0], 'off', simulate_off_impact=True)
    model.assert_not_called()
    assert row['verdict'] == 'SIMULATED_ATTACK_SUCCESS'
    assert row['simulated_attack_success'] is True
    assert row['attack_success'] is None and row['measurement_eligible'] is False
    current = {'evaluator_version': EVALUATOR_VERSION, 'defense_mode': 'off',
               'workflow_profile_version': WORKFLOW_PROFILE_VERSION}
    assert comparable_reports(current, dict(current))
    assert not comparable_reports(current, {'evaluator_version': 'unknown/legacy'})
    assert not comparable_reports(current, {'evaluator_version': EVALUATOR_VERSION})
    assert not comparable_reports(current, {**current, 'simulate_off_impact': True})
    with pytest.raises(ValueError, match='legacy/mixed'):
        h.statistics([{'evaluator_version': 'unknown/legacy'}])
    for harness, filename in [(full_h, f'{full_h.REPORT_PREFIX}_off.json'), (retrieval_h, 'retrieval_guard_off.json')]:
        historical = tmp_path / filename
        historical.write_text('historical artifact', encoding='utf-8')
        path = harness.save_report(current, tmp_path)
        assert path.parent.name == EVALUATOR_VERSION
        assert historical.read_text(encoding='utf-8') == 'historical artifact'
