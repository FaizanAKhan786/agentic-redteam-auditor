import pytest
from pathlib import Path
from auditor.report import generate_report, log_transcript
from auditor.scoring import Finding


class TestGenerateReport:
    def test_produces_markdown_file(self, sample_finding, tmp_reports_dir):
        report_path = generate_report(
            findings=[sample_finding],
            output_dir=tmp_reports_dir,
        )
        assert Path(report_path).exists()
        assert report_path.endswith(".md")

    def test_report_contains_required_sections(self, sample_finding, tmp_reports_dir):
        report_path = generate_report(
            findings=[sample_finding],
            output_dir=tmp_reports_dir,
        )
        content = Path(report_path).read_text(encoding="utf-8")
        assert "Executive Summary" in content
        assert "Findings Summary" in content
        assert "Detailed Findings" in content
        assert "Methodology" in content

    def test_report_contains_finding_details(self, sample_finding, tmp_reports_dir):
        report_path = generate_report(
            findings=[sample_finding],
            output_dir=tmp_reports_dir,
        )
        content = Path(report_path).read_text(encoding="utf-8")
        assert "direct_prompt_injection" in content
        assert "High" in content
        assert "Mitigation" in content

    def test_empty_findings_produces_valid_report(self, tmp_reports_dir):
        report_path = generate_report(
            findings=[],
            output_dir=tmp_reports_dir,
        )
        assert Path(report_path).exists()
        content = Path(report_path).read_text(encoding="utf-8")
        assert "No vulnerabilities found" in content

    def test_report_with_target_info(self, sample_finding, tmp_reports_dir, sample_target_info):
        report_path = generate_report(
            findings=[sample_finding],
            target_info=sample_target_info,
            output_dir=tmp_reports_dir,
        )
        content = Path(report_path).read_text(encoding="utf-8")
        assert "Target System" in content


class TestLogTranscript:
    def test_creates_jsonl_file(self, tmp_reports_dir):
        log_transcript(
            attempt_data={"module": "test", "payload": "test"},
            verdict_data={"succeeded": True, "confidence": 0.9, "evidence": "test"},
            output_dir=tmp_reports_dir,
        )
        jsonl_path = tmp_reports_dir / "transcripts.jsonl"
        assert jsonl_path.exists()

    def test_appends_to_existing_file(self, tmp_reports_dir):
        for i in range(3):
            log_transcript(
                attempt_data={"module": f"test_{i}"},
                verdict_data={"succeeded": True},
                output_dir=tmp_reports_dir,
            )
        jsonl_path = tmp_reports_dir / "transcripts.jsonl"
        lines = jsonl_path.read_text().strip().split("\n")
        assert len(lines) == 3
