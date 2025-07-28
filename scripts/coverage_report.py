#!/usr/bin/env python3
"""
Coverage reporting script for Heimdall.

This script generates comprehensive coverage reports and provides
insights into code coverage trends and areas for improvement.
"""

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

PROJECT_ROOT = Path(__file__).parent.parent


class CoverageReporter:
    """Enhanced coverage reporter with trend analysis."""
    
    def __init__(self):
        self.project_root = PROJECT_ROOT
        self.coverage_dir = self.project_root / "htmlcov"
        self.coverage_xml = self.project_root / "coverage.xml"
        self.coverage_json = self.project_root / "coverage.json"
        self.history_file = self.project_root / ".coverage-history.json"
    
    def generate_reports(
        self,
        source_dirs: List[str] = None,
        show_missing: bool = True,
        include_branches: bool = True,
        min_coverage: float = 80.0
    ) -> Dict[str, Any]:
        """
        Generate comprehensive coverage reports.
        
        Args:
            source_dirs: Source directories to analyze
            show_missing: Show missing lines in report
            include_branches: Include branch coverage
            min_coverage: Minimum coverage threshold
            
        Returns:
            Dict containing coverage statistics
        """
        if source_dirs is None:
            source_dirs = ["nitro_wallet", "application", "config"]
        
        print("📊 Generating coverage reports...")
        
        # Generate different report formats
        reports = {}
        
        # Generate terminal report
        print("   • Terminal report...")
        reports["terminal"] = self._generate_terminal_report(show_missing)
        
        # Generate HTML report
        print("   • HTML report...")
        reports["html"] = self._generate_html_report()
        
        # Generate XML report  
        print("   • XML report...")
        reports["xml"] = self._generate_xml_report()
        
        # Generate JSON report
        print("   • JSON report...")
        reports["json"] = self._generate_json_report()
        
        # Parse coverage statistics
        stats = self._parse_coverage_stats()
        
        # Update coverage history
        self._update_coverage_history(stats)
        
        # Generate summary
        summary = self._generate_summary(stats, min_coverage)
        
        # Generate trend analysis
        trends = self._analyze_trends()
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "statistics": stats,
            "summary": summary,
            "trends": trends,
            "reports": reports,
            "passed_threshold": stats.get("total_coverage", 0) >= min_coverage
        }
        
        self._print_summary(result)
        
        return result
    
    def _generate_terminal_report(self, show_missing: bool = True) -> Dict[str, Any]:
        """Generate terminal coverage report."""
        cmd = ["coverage", "report"]
        
        if show_missing:
            cmd.append("--show-missing")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _generate_html_report(self) -> Dict[str, Any]:
        """Generate HTML coverage report."""
        cmd = ["coverage", "html", "-d", str(self.coverage_dir)]
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return {
                "success": result.returncode == 0,
                "path": str(self.coverage_dir / "index.html"),
                "error": result.stderr if result.returncode != 0 else None
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _generate_xml_report(self) -> Dict[str, Any]:
        """Generate XML coverage report."""
        cmd = ["coverage", "xml", "-o", str(self.coverage_xml)]
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                "success": result.returncode == 0,
                "path": str(self.coverage_xml),
                "error": result.stderr if result.returncode != 0 else None
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _generate_json_report(self) -> Dict[str, Any]:
        """Generate JSON coverage report."""
        cmd = ["coverage", "json", "-o", str(self.coverage_json)]
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                "success": result.returncode == 0,
                "path": str(self.coverage_json),
                "error": result.stderr if result.returncode != 0 else None
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _parse_coverage_stats(self) -> Dict[str, Any]:
        """Parse coverage statistics from reports."""
        stats = {}
        
        # Try to parse from JSON report first
        if self.coverage_json.exists():
            try:
                with open(self.coverage_json) as f:
                    data = json.load(f)
                
                totals = data.get("totals", {})
                stats = {
                    "total_coverage": round(totals.get("percent_covered", 0), 2),
                    "total_statements": totals.get("num_statements", 0),
                    "covered_statements": totals.get("covered_lines", 0),
                    "missing_statements": totals.get("missing_lines", 0),
                    "excluded_statements": totals.get("excluded_lines", 0),
                    "branch_coverage": round(totals.get("percent_covered_display", 0), 2),
                    "files": {}
                }
                
                # Add per-file statistics
                for filename, file_data in data.get("files", {}).items():
                    summary = file_data.get("summary", {})
                    stats["files"][filename] = {
                        "coverage": round(summary.get("percent_covered", 0), 2),
                        "statements": summary.get("num_statements", 0),
                        "covered": summary.get("covered_lines", 0),
                        "missing": summary.get("missing_lines", 0)
                    }
            
            except Exception as e:
                print(f"⚠️  Warning: Could not parse JSON coverage report: {e}")
        
        # Fallback to XML parsing
        if not stats and self.coverage_xml.exists():
            try:
                tree = ET.parse(self.coverage_xml)
                root = tree.getroot()
                
                # Parse total coverage
                total_lines = 0
                covered_lines = 0
                
                for class_elem in root.findall(".//class"):
                    lines_elem = class_elem.find(".//lines")
                    if lines_elem is not None:
                        lines_covered = int(lines_elem.get("covered", "0"))
                        lines_total = int(lines_elem.get("valid", "0"))
                        
                        covered_lines += lines_covered
                        total_lines += lines_total
                
                if total_lines > 0:
                    coverage_percent = (covered_lines / total_lines) * 100
                    stats = {
                        "total_coverage": round(coverage_percent, 2),
                        "total_statements": total_lines,
                        "covered_statements": covered_lines,
                        "missing_statements": total_lines - covered_lines
                    }
            
            except Exception as e:
                print(f"⚠️  Warning: Could not parse XML coverage report: {e}")
        
        return stats
    
    def _update_coverage_history(self, stats: Dict[str, Any]):
        """Update coverage history for trend analysis."""
        try:
            # Load existing history
            history = []
            if self.history_file.exists():
                with open(self.history_file) as f:
                    history = json.load(f)
            
            # Add current stats
            entry = {
                "timestamp": datetime.now().isoformat(),
                "coverage": stats.get("total_coverage", 0),
                "statements": stats.get("total_statements", 0),
                "covered": stats.get("covered_statements", 0)
            }
            
            history.append(entry)
            
            # Keep only last 100 entries
            history = history[-100:]
            
            # Save updated history
            with open(self.history_file, "w") as f:
                json.dump(history, f, indent=2)
        
        except Exception as e:
            print(f"⚠️  Warning: Could not update coverage history: {e}")
    
    def _analyze_trends(self) -> Dict[str, Any]:
        """Analyze coverage trends."""
        trends = {
            "trend": "stable",
            "change": 0,
            "history_available": False
        }
        
        try:
            if not self.history_file.exists():
                return trends
            
            with open(self.history_file) as f:
                history = json.load(f)
            
            if len(history) < 2:
                return trends
            
            trends["history_available"] = True
            
            # Calculate trend over last 10 runs
            recent_history = history[-10:]
            if len(recent_history) >= 2:
                old_coverage = recent_history[0]["coverage"]
                new_coverage = recent_history[-1]["coverage"]
                
                change = new_coverage - old_coverage
                trends["change"] = round(change, 2)
                
                if change > 1:
                    trends["trend"] = "improving"
                elif change < -1:
                    trends["trend"] = "declining"
                else:
                    trends["trend"] = "stable"
        
        except Exception as e:
            print(f"⚠️  Warning: Could not analyze coverage trends: {e}")
        
        return trends
    
    def _generate_summary(self, stats: Dict[str, Any], min_coverage: float) -> Dict[str, Any]:
        """Generate coverage summary."""
        total_coverage = stats.get("total_coverage", 0)
        
        summary = {
            "status": "passed" if total_coverage >= min_coverage else "failed",
            "coverage": total_coverage,
            "threshold": min_coverage,
            "gap": max(0, min_coverage - total_coverage)
        }
        
        # Find files with low coverage
        low_coverage_files = []
        for filename, file_stats in stats.get("files", {}).items():
            if file_stats["coverage"] < min_coverage:
                low_coverage_files.append({
                    "file": filename,
                    "coverage": file_stats["coverage"],
                    "gap": min_coverage - file_stats["coverage"]
                })
        
        summary["low_coverage_files"] = sorted(
            low_coverage_files,
            key=lambda x: x["gap"],
            reverse=True
        )[:10]  # Top 10 files needing attention
        
        return summary
    
    def _print_summary(self, result: Dict[str, Any]):
        """Print coverage summary to console."""
        stats = result["statistics"]
        summary = result["summary"]
        trends = result["trends"]
        
        print("\n" + "="*60)
        print("📊 COVERAGE REPORT SUMMARY")
        print("="*60)
        
        # Overall coverage
        status_icon = "✅" if summary["status"] == "passed" else "❌"
        print(f"Overall Coverage: {status_icon} {stats.get('total_coverage', 0):.2f}%")
        print(f"Threshold: {summary['threshold']:.1f}%")
        
        if summary["gap"] > 0:
            print(f"Gap to Threshold: {summary['gap']:.2f}%")
        
        # Trend information
        if trends["history_available"]:
            trend_icon = {"improving": "📈", "declining": "📉", "stable": "➡️"}[trends["trend"]]
            print(f"Trend: {trend_icon} {trends['trend'].title()} ({trends['change']:+.2f}%)")
        
        # Statistics
        print(f"\nStatements: {stats.get('total_statements', 0):,}")
        print(f"Covered: {stats.get('covered_statements', 0):,}")
        print(f"Missing: {stats.get('missing_statements', 0):,}")
        
        # Low coverage files
        low_cov_files = summary.get("low_coverage_files", [])
        if low_cov_files:
            print(f"\n🎯 Files needing attention ({len(low_cov_files)}):")
            for file_info in low_cov_files[:5]:  # Show top 5
                print(f"   • {file_info['file']}: {file_info['coverage']:.1f}% (-{file_info['gap']:.1f}%)")
        
        # Report locations
        print(f"\n📄 Reports generated:")
        reports = result["reports"]
        if reports.get("html", {}).get("success"):
            print(f"   • HTML: {reports['html']['path']}")
        if reports.get("xml", {}).get("success"):
            print(f"   • XML: {reports['xml']['path']}")
        if reports.get("json", {}).get("success"):
            print(f"   • JSON: {reports['json']['path']}")
        
        print("="*60)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate coverage reports for Heimdall")
    parser.add_argument(
        "--min-coverage",
        type=float,
        default=80.0,
        help="Minimum coverage threshold (default: 80.0)"
    )
    parser.add_argument(
        "--no-missing",
        action="store_true",
        help="Don't show missing lines in terminal report"
    )
    parser.add_argument(
        "--source-dir",
        action="append",
        help="Source directories to analyze (can be used multiple times)"
    )
    
    args = parser.parse_args()
    
    reporter = CoverageReporter()
    
    result = reporter.generate_reports(
        source_dirs=args.source_dir,
        show_missing=not args.no_missing,
        min_coverage=args.min_coverage
    )
    
    # Exit with appropriate code
    sys.exit(0 if result["passed_threshold"] else 1)


if __name__ == "__main__":
    main()