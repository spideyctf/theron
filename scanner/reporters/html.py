"""HTML reporter — generates an interactive HTML report with filtering and SBOM view."""

import json
from scanner.models import ScanResult, Severity


def generate_html_report(result: ScanResult) -> str:
    summary = result.summary
    findings_json = json.dumps([f.to_dict() for f in result.findings])
    sbom_json = json.dumps(result.sbom, indent=2) if result.sbom else "null"

    by_sev = summary["by_severity"]
    counts = {sev.value: by_sev.get(sev.value, 0) for sev in Severity}

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Security Scan Report — {summary['repo']}</title>
    <style>
        :root {{
            --bg: #0d1117; --card-bg: #161b22; --border: #30363d;
            --text: #c9d1d9; --text-dim: #8b949e; --accent: #58a6ff;
            --critical: #f85149; --high: #ff7b72; --medium: #d29922;
            --low: #58a6ff; --info: #8b949e; --green: #3fb950;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ font-size: 1.8rem; margin-bottom: 8px; }}
        h2 {{ font-size: 1.3rem; margin: 24px 0 12px; }}
        .header {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .meta {{ color: var(--text-dim); font-size: 0.9rem; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 12px; margin: 16px 0; }}
        .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
        .stat-card .num {{ font-size: 2rem; font-weight: bold; }}
        .stat-card .label {{ font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; }}
        .stat-critical .num {{ color: var(--critical); }}
        .stat-high .num {{ color: var(--high); }}
        .stat-medium .num {{ color: var(--medium); }}
        .stat-low .num {{ color: var(--low); }}
        .stat-info .num {{ color: var(--info); }}
        .stat-total .num {{ color: var(--accent); }}
        .filters {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }}
        .filter-btn {{ background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.85rem; }}
        .filter-btn:hover {{ border-color: var(--accent); }}
        .filter-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
        .finding {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
        .finding-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }}
        .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
        .badge-critical {{ background: var(--critical); color: #fff; }}
        .badge-high {{ background: var(--high); color: #fff; }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); color: #fff; }}
        .badge-info {{ background: var(--info); color: #000; }}
        .badge-category {{ background: var(--border); color: var(--text); }}
        .finding-title {{ font-weight: 600; font-size: 1rem; }}
        .finding-meta {{ color: var(--text-dim); font-size: 0.85rem; margin: 4px 0; }}
        .finding-desc {{ margin: 8px 0; font-size: 0.9rem; }}
        .finding-rec {{ background: rgba(63,185,80,0.1); border-left: 3px solid var(--green); padding: 8px 12px; margin: 8px 0; font-size: 0.85rem; border-radius: 0 4px 4px 0; }}
        .code-block {{ background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 12px; font-family: 'SF Mono', Monaco, monospace; font-size: 0.8rem; overflow-x: auto; margin: 8px 0; white-space: pre; }}
        .tab-bar {{ display: flex; gap: 4px; border-bottom: 1px solid var(--border); margin-bottom: 16px; }}
        .tab {{ padding: 8px 16px; cursor: pointer; border-bottom: 2px solid transparent; color: var(--text-dim); }}
        .tab.active {{ border-bottom-color: var(--accent); color: var(--accent); }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
        .sbom-pre {{ background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 12px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; max-height: 600px; overflow-y: auto; }}
        .no-findings {{ text-align: center; padding: 40px; color: var(--green); font-size: 1.2rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 AI Infrastructure Security Scan Report</h1>
            <p class="meta">
                <strong>Repository:</strong> {summary['repo']} &nbsp;|&nbsp;
                <strong>Branch:</strong> {summary['branch']} &nbsp;|&nbsp;
                <strong>Files Scanned:</strong> {summary['files_scanned']} &nbsp;|&nbsp;
                <strong>Modules:</strong> {', '.join(summary['modules_run'])} &nbsp;|&nbsp;
                <strong>Duration:</strong> {summary['scan_duration_seconds']}s
            </p>
        </div>
        <div class="summary-grid">
            <div class="stat-card stat-total"><div class="num">{summary['total_findings']}</div><div class="label">Total</div></div>
            <div class="stat-card stat-critical"><div class="num">{counts['CRITICAL']}</div><div class="label">Critical</div></div>
            <div class="stat-card stat-high"><div class="num">{counts['HIGH']}</div><div class="label">High</div></div>
            <div class="stat-card stat-medium"><div class="num">{counts['MEDIUM']}</div><div class="label">Medium</div></div>
            <div class="stat-card stat-low"><div class="num">{counts['LOW']}</div><div class="label">Low</div></div>
            <div class="stat-card stat-info"><div class="num">{counts['INFO']}</div><div class="label">Info</div></div>
        </div>
        <div class="tab-bar">
            <div class="tab active" onclick="switchTab('findings')">Findings ({summary['total_findings']})</div>
            <div class="tab" onclick="switchTab('sbom')">SBOM</div>
        </div>
        <div id="tab-findings" class="tab-content active">
            <div class="filters">
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn" onclick="filterFindings('CRITICAL', this)">Critical</button>
                <button class="filter-btn" onclick="filterFindings('HIGH', this)">High</button>
                <button class="filter-btn" onclick="filterFindings('MEDIUM', this)">Medium</button>
                <button class="filter-btn" onclick="filterFindings('LOW', this)">Low</button>
                <button class="filter-btn" onclick="filterFindings('INFO', this)">Info</button>
            </div>
            <div id="findings-list"></div>
        </div>
        <div id="tab-sbom" class="tab-content">
            <h2>Software Bill of Materials (SBOM)</h2>
            <p class="meta">CycloneDX 1.5 format — auto-generated from dependency manifests</p>
            <pre class="sbom-pre" id="sbom-content"></pre>
        </div>
    </div>
    <script>
        const findings = {findings_json};
        const sbom = {sbom_json};
        function esc(s) {{ return s ? s.replace(/</g,'&lt;').replace(/>/g,'&gt;') : ''; }}
        function renderFindings(filter) {{
            const list = document.getElementById('findings-list');
            const filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter);
            if (filtered.length === 0) {{ list.innerHTML = '<div class="no-findings">✅ No findings at this severity level</div>'; return; }}
            list.innerHTML = filtered.map((f, i) => `
                <div class="finding" data-severity="${{f.severity}}">
                    <div class="finding-header">
                        <span class="badge badge-${{f.severity.toLowerCase()}}">${{f.severity}}</span>
                        <span class="badge badge-category">${{f.category}}</span>
                        <span class="finding-title">${{esc(f.title)}}</span>
                    </div>
                    <div class="finding-meta">📁 ${{esc(f.file_path)}}:${{f.line_number || 'N/A'}} &nbsp;|&nbsp; 🏷️ ${{f.cwe || 'N/A'}} &nbsp;|&nbsp; 🎯 ${{f.confidence}} &nbsp;|&nbsp; 📦 ${{f.module}}</div>
                    <div class="finding-desc">${{esc(f.description)}}</div>
                    ${{f.recommendation ? `<div class="finding-rec">💡 <strong>Recommendation:</strong> ${{esc(f.recommendation)}}</div>` : ''}}
                    ${{f.code_snippet ? `<div class="code-block">${{esc(f.code_snippet)}}</div>` : ''}}
                </div>
            `).join('');
        }}
        function filterFindings(severity, btn) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderFindings(severity);
        }}
        function switchTab(tabName) {{
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('tab-' + tabName).classList.add('active');
        }}
        renderFindings('all');
        document.getElementById('sbom-content').textContent = sbom ? JSON.stringify(sbom, null, 2) : 'No SBOM generated (SCA module not run or no dependencies found)';
    </script>
</body>
</html>"""
    return html


def save_html_report(result: ScanResult, output_path: str):
    with open(output_path, "w") as f:
        f.write(generate_html_report(result))
