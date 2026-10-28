import { useEffect, useRef, useState } from 'react'
import { ArrowDownToLine, ArrowUpRight, Check, ChevronRight, CircleHelp, Copy, FileCode2, GitBranch, Github, Layers3, LoaderCircle, Plus, Search, ShieldCheck, SlidersHorizontal, X } from 'lucide-react'
import { api, downloadBlob, filterFindings, modules, severities, sourceUrl } from './api'
import type { Finding, Health, ScanJob, ScanResult } from './api'
import { sampleReport } from './sample'
import { Dependencies, ProjectDetails, ScanDetails } from './ReportDetails'

const moduleNames: Record<string, string> = { ai: 'AI security', sast: 'Static analysis', sca: 'Dependencies', agentic: 'Agentic security' }
const message = (error: unknown) => error instanceof Error ? error.message : 'Something went wrong. Please try again.'
const relativeTime = (date: string) => new Date(date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
const severityName = (value: string) => value.charAt(0) + value.slice(1).toLowerCase()

export default function App() {
  const [health, setHealth] = useState<Health | null>(null)
  const [connection, setConnection] = useState<'connecting' | 'online' | 'offline'>('connecting')
  const [jobs, setJobs] = useState<ScanJob[]>([])
  const [active, setActive] = useState('sample')
  const [job, setJob] = useState<ScanJob | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [showHelp, setShowHelp] = useState(false)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('all')
  const [module, setModule] = useState('all')
  const [status, setStatus] = useState('all')
  const [tab, setTab] = useState('findings')
  const sample = active === 'sample'
  const result = sample ? sampleReport : job?.result
  const activeFindings = result ? (tab === 'context' ? result.context_findings || [] : result.findings) : []
  const findings = filterFindings(activeFindings, search, severity, module, status)
  const busy = !sample && (!job || job.status === 'queued' || job.status === 'running')

  useEffect(() => {
    let alive = true
    const refresh = async () => {
      try {
        const [nextHealth, nextJobs] = await Promise.all([api.health(), api.list()])
        if (alive) { setHealth(nextHealth); setJobs(nextJobs); setConnection('online') }
      } catch { if (alive) setConnection('offline') }
    }
    void refresh()
    const interval = setInterval(() => void refresh(), 3000)
    return () => { alive = false; clearInterval(interval) }
  }, [])

  useEffect(() => {
    setSelected(null); setSearch(''); setSeverity('all'); setModule('all'); setStatus('all'); setError(''); setJob(null); setTab('findings')
    if (active === 'sample') return
    let alive = true
    let timer: ReturnType<typeof setTimeout>
    const refresh = async () => {
      try {
        const next = await api.get(active)
        if (!alive) return
        setJob(next); setError('')
        if (next.status === 'queued' || next.status === 'running') timer = setTimeout(() => void refresh(), 1500)
      } catch (err) { if (alive) setError(message(err)) }
    }
    void refresh()
    return () => { alive = false; clearTimeout(timer) }
  }, [active])

  useEffect(() => {
    if (selected && !findings.includes(selected)) setSelected(null)
  }, [search, severity, module, status, selected, findings])

  async function exportReport(format: 'json' | 'sarif') {
    try {
      if (sample) {
        if (format === 'json') downloadBlob(JSON.stringify(sampleReport, null, 2), 'theron_sample.json')
        return
      }
      const response = await fetch('/api/scans/' + encodeURIComponent(active) + '/report?format=' + format)
      if (!response.ok) throw new Error('Could not download the report. Try again.')
      downloadBlob(await response.text(), 'theron_' + result?.repo_full_name.replace('/', '_') + '.' + format)
    } catch (err) { setError(message(err)) }
  }

  return <div className="app-shell">
    <aside className="sidebar" aria-label="Workspace navigation">
      <a href="#" onClick={e => { e.preventDefault(); setActive('sample') }} className="brand" aria-label="Theron home"><span className="brand-mark">T</span><span>theron<span className="brand-period">.</span></span></a>
      <div className="workspace-label"><span className="workspace-icon">AF</span><div>Local workspace<small>Personal environment</small></div><span className="local-dot" /></div>
      <div className="sidebar-section-label">WORKSPACE</div>
      <div className="nav-current"><Layers3 size={16} /> Repository scans <span>{jobs.length}</span></div>
      <button className="sidebar-new" onClick={() => setShowForm(true)}><Plus size={15} /> New scan</button>
      <div className="sidebar-section-label recent-label">SESSION SCANS</div>
      <div className="scan-history">
        {jobs.length === 0 ? <p className="history-empty">Your scans will appear here.<br />History lasts for this session.</p> : jobs.map(item => <button className={'history-item ' + (active === item.id ? 'active' : '')} key={item.id} onClick={() => setActive(item.id)}>
          <span className={'job-dot ' + item.status} /><span>{item.repository.split('/').pop()}<small>{relativeTime(item.created_at)} · {item.status}</small></span>
        </button>)}
      </div>
      <div className="sample-navigation"><div className="sidebar-section-label">EXPLORE</div><button className={'history-item ' + (sample ? 'active' : '')} onClick={() => setActive('sample')}><FileCode2 size={16} /><span>Example scan<small>Sample data · 8 findings</small></span><ChevronRight size={13} /></button></div>
      <div className="sidebar-bottom">
        <button onClick={() => setShowHelp(true)}><CircleHelp size={16} /> Getting started <ArrowUpRight size={13} /></button>
        <div className="connection"><span className={'connection-dot ' + connection} />{connection === 'online' ? 'Local engine connected' : connection === 'connecting' ? 'Connecting to engine' : 'Engine offline'}<span className="version">v1.0</span></div>
      </div>
    </aside>

    <div className="workspace">
      <header className="topbar"><div className="breadcrumb">Workspace<ChevronRight size={13} /><span>Repository scans</span></div><div className="topbar-right"><span className="environment">LOCAL</span><button className="icon-button" aria-label="Open getting started" onClick={() => setShowHelp(true)}><CircleHelp size={17} /></button></div></header>
      <main>
        <div className="page-heading"><div><div className="eyebrow"><span className="blue-line" />AI & AGENT SECURITY</div><h1>Repository scans<span className="title-dot">.</span></h1><p>A clear view of what needs your attention.</p></div><button className="primary-button" onClick={() => setShowForm(true)}><Plus size={16} />New scan</button></div>
        <label className="mobile-scan-picker"><span>Current scan</span><select aria-label="Select current scan" value={active} onChange={e => setActive(e.target.value)}><option value="sample">Example scan · sample data</option>{jobs.map(item => <option key={item.id} value={item.id}>{item.repository} · {item.status}</option>)}</select></label>

        {connection === 'offline' && <div className="notice" role="status"><span>The local engine is offline. Start <code>python -m scanner.web</code> to run live scans.</span><button onClick={() => setShowHelp(true)}>Setup guide <ArrowUpRight size={13} /></button></div>}
        {error && <div className="error-banner" role="alert">{error}<button aria-label="Dismiss error" onClick={() => setError('')}><X size={16} /></button></div>}

        <section className="scan-surface" aria-label="Scan results">
          <div className="scan-heading"><div className="repository-heading"><Github size={20} /><div><h2>{sample ? sampleReport.repo_full_name : job?.repository || jobs.find(item => item.id === active)?.repository || 'Loading scan'}</h2><div className="scan-meta"><span><GitBranch size={12} />{result?.branch || job?.branch || 'Default branch'}</span><i />{result ? <><span>{result.files_scanned} files scanned</span><i /><span>{result.scan_duration_seconds}s duration</span></> : <span>{job?.status || 'Loading'}</span>}</div></div></div><div className="scan-heading-actions">{sample ? <span className="sample-badge">SAMPLE REPORT</span> : job?.status === 'completed' ? <span className="complete-label"><Check size={13} /> Scan complete</span> : null}<button className="quiet-button" disabled={!result} onClick={() => void exportReport('json')}><ArrowDownToLine size={14} />JSON</button><button className="quiet-button" disabled={!result || sample} title={sample ? 'SARIF export is available for live scans' : 'Download SARIF report'} onClick={() => void exportReport('sarif')}>SARIF<ArrowDownToLine size={14} /></button></div></div>

          {sample && <div className="sample-strip"><span className="sample-strip-dot" />Illustrative findings. Run a scan to see evidence from your repository.<button onClick={() => setShowForm(true)}>Scan a repository <ArrowUpRight size={13} /></button></div>}
          {result && <>
            <div className="summary-strip"><div className="summary-total"><strong>{result.findings.length}</strong><span>Application findings</span></div>{severities.map(s => <button key={s} className={'severity-summary ' + (severity === s ? 'selected' : '')} onClick={() => { setTab('findings'); setSeverity(severity === s ? 'all' : s) }}><span className={'severity-dot ' + s.toLowerCase()} /><strong>{result.findings.filter(f => f.severity === s).length}</strong><span>{severityName(s)}</span></button>)}<div className="summary-new"><span>{result.findings.filter(f => f.status === 'new').length} new</span><span>{result.findings.filter(f => f.status === 'existing').length} existing</span></div></div>
            <div className="results-tabs"><div role="tablist" aria-label="Report views">{[['findings', `Findings (${result.findings.length})`], ['context', `Tests / examples (${result.context_findings?.length || 0})`], ['dependencies', 'Dependencies / SBOM'], ['profile', 'Project profile'], ['details', 'Scan details']].map(([id, label]) => <button key={id} role="tab" id={`tab-${id}`} aria-selected={tab === id} aria-controls={`panel-${id}`} className={tab === id ? 'active-tab' : ''} onClick={() => { setTab(id); setSelected(null) }}>{label}</button>)}</div><div className="module-indicator" title={result.modules_run.join(', ')}><ShieldCheck size={13} />{result.modules_run.length} modules completed</div></div>
            {result.findings.some(finding => finding.severity === 'INFO') && <div className="coverage-strip" role="status"><span>{result.findings.filter(finding => finding.severity === 'INFO').length} informational notices. Review skipped checks, unresolved versions and advisory availability.</span><button onClick={() => { setTab('findings'); setSeverity('INFO'); setModule('all'); setStatus('all'); setSearch('') }}>Review notices</button></div>}
            {(tab === 'findings' || tab === 'context') && <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
              {tab === 'context' && <div className="coverage-strip">These detections originate in tests, examples or documentation. They are retained for review and excluded from application totals and CI failure thresholds.</div>}
            <div className="filterbar"><label className="search-input"><Search size={15} /><input aria-label="Search findings" placeholder="Search findings, files, or rules…" value={search} onChange={e => setSearch(e.target.value)} /><kbd>/</kbd></label><div className="filter-controls"><SlidersHorizontal size={14} /><label><span className="sr-only">Filter by severity</span><select value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">All severities</option>{severities.map(s => <option key={s} value={s}>{severityName(s)}</option>)}</select></label><label><span className="sr-only">Filter by module</span><select value={module} onChange={e => setModule(e.target.value)}><option value="all">All modules</option>{modules.map(m => <option key={m} value={m}>{moduleNames[m]}</option>)}<option value="coverage">Coverage notices</option></select></label><label><span className="sr-only">Filter by status</span><select value={status} onChange={e => setStatus(e.target.value)}><option value="all">All statuses</option><option value="new">New</option><option value="existing">Existing</option></select></label></div></div>
            <FindingsTable findings={findings} selected={selected} onSelect={setSelected} filtered={Boolean(search || severity !== 'all' || module !== 'all' || status !== 'all')} onClear={() => { setSearch(''); setSeverity('all'); setModule('all'); setStatus('all') }} />
            <div className="table-footer"><span>Showing {findings.length} of {activeFindings.length} findings</span><span><span className="report-only-dot" />Report only · Review before contributing</span></div></div>}
            {tab === 'dependencies' && <div role="tabpanel" id="panel-dependencies" aria-labelledby="tab-dependencies"><Dependencies result={result} /></div>}
            {tab === 'profile' && <div role="tabpanel" id="panel-profile" aria-labelledby="tab-profile"><ProjectDetails result={result} /></div>}
            {tab === 'details' && <div role="tabpanel" id="panel-details" aria-labelledby="tab-details"><ScanDetails result={result} job={job} sample={sample} /></div>}
          </>}
          {!result && <div className="scan-state" role="status">{busy && !error ? <><LoaderCircle className="spin" size={25} /><h3>{job?.status === 'queued' ? 'Waiting for the scanner' : 'Scanning your repository'}</h3><p>{job?.status === 'queued' ? 'Another scan is running. This scan will start next.' : 'Reading repository files and checking the selected modules.'}</p><span className="state-note">Results will appear here when the scan finishes.</span></> : <><ShieldCheck size={27} /><h3>{job?.status === 'failed' ? 'This scan could not finish' : 'Scan unavailable'}</h3><p>{job?.error || error || 'Start a new scan to inspect your repository.'}</p><button className="quiet-button" onClick={() => setShowForm(true)}>Start another scan <ArrowUpRight size={14} /></button></>}</div>}
        </section>
        <footer className="workspace-footer"><span><ShieldCheck size={13} /> Evidence first. Better contributions follow.</span><span>THERON / OPEN SOURCE SECURITY</span></footer>
      </main>
    </div>
    {selected && result && <FindingPanel finding={selected} result={result} sample={sample} onClose={() => setSelected(null)} />}
    {showForm && <NewScanDialog health={health} connected={connection === 'online'} onClose={() => setShowForm(false)} onStarted={id => { setActive(id); setShowForm(false) }} />}
    {showHelp && <Dialog title="Your local security workspace" subtitle="A few commands, then you’re ready to scan." onClose={() => setShowHelp(false)}><div className="help-content"><h3>1. Start the engine</h3><p>From the project root, install the web extra and set a GitHub token in the backend environment.</p><pre>python -m pip install -e ".[web]"{'\n'}python -m scanner.web</pre><h3>2. Open the workspace</h3><p>For development, run these commands inside <code>frontend/</code>.</p><pre>npm install{'\n'}npm run dev</pre><p>The backend reads <code>GITHUB_TOKEN</code>. The browser never receives it. Scan history lasts until the engine restarts.</p><p>To serve a production build, run <code>npm run build</code> then restart the engine and open <code>http://127.0.0.1:8000</code>.</p></div></Dialog>}
    <SearchShortcut />
  </div>
}

function SearchShortcut() {
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes((event.target as HTMLElement).tagName)) {
        event.preventDefault(); document.querySelector<HTMLInputElement>('[aria-label="Search findings"]')?.focus()
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])
  return null
}

function FindingsTable({ findings, selected, onSelect, filtered, onClear }: { findings: Finding[]; selected: Finding | null; onSelect: (finding: Finding) => void; filtered: boolean; onClear: () => void }) {
  if (!findings.length) return <div className="scan-state"><ShieldCheck size={26} /><h3>{filtered ? 'No findings match these filters' : 'No findings reported'}</h3><p>{filtered ? 'Try a different search or clear your filters.' : 'The selected checks did not report findings. This is not a guarantee that the repository is free of vulnerabilities.'}</p>{filtered && <button className="quiet-button" onClick={onClear}>Clear filters</button>}</div>
  return <div className="table-scroll"><table className="findings-table"><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Status</th><th><span className="sr-only">Details</span></th></tr></thead><tbody>{findings.map((f, i) => <tr key={f.fingerprint || f.rule_id + ':' + i} className={selected === f ? 'selected-row' : ''} onClick={() => onSelect(f)}><td><span className={'severity-badge ' + f.severity.toLowerCase()}><span className="severity-dot" />{severityName(f.severity)}</span></td><td><button className="finding-link" onClick={e => { e.stopPropagation(); onSelect(f) }}>{f.title}</button><div className="finding-subtitle">{moduleNames[f.module] || f.module}<span>·</span><code>{f.rule_id || f.category}</code><span className="maturity-tag">{f.maturity}</span></div></td><td className="location"><code>{f.file_path}</code><span>Line {f.line_number ?? '—'}</span></td><td><span className={'status-tag ' + f.status}>{f.status === 'existing' ? 'Existing' : 'New'}</span></td><td><ChevronRight size={15} /></td></tr>)}</tbody></table></div>
}

function Dialog({ title, subtitle, onClose, children, panel = false }: { title: string; subtitle?: string; onClose: () => void; children: React.ReactNode; panel?: boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  const closeRef = useRef(onClose)
  closeRef.current = onClose
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const element = ref.current
    element?.querySelector<HTMLElement>('input, button, select, a[href]')?.focus()
    const oldOverflow = document.body.style.overflow; document.body.style.overflow = 'hidden'
    const handle = (event: KeyboardEvent) => {
      if (event.key === 'Escape') closeRef.current()
      if (event.key !== 'Tab' || !element) return
      const focusable = Array.from(element.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), a[href], textarea'))
      const first = focusable[0], last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
    }
    document.addEventListener('keydown', handle)
    return () => { document.removeEventListener('keydown', handle); document.body.style.overflow = oldOverflow; previous?.focus() }
  }, [])
  return <div className={'overlay ' + (panel ? 'panel-overlay' : '')} onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}><div ref={ref} className={panel ? 'detail-panel' : 'dialog'} role="dialog" aria-modal="true" aria-label={title}><div className="dialog-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div><button className="icon-button" onClick={onClose} aria-label="Close dialog"><X size={19} /></button></div>{children}</div></div>
}

function NewScanDialog({ health, connected, onClose, onStarted }: { health: Health | null; connected: boolean; onClose: () => void; onStarted: (id: string) => void }) {
  const [repository, setRepository] = useState('')
  const [branch, setBranch] = useState('')
  const [enabled, setEnabled] = useState<string[]>([...modules])
  const [experimental, setExperimental] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const ready = connected && health?.github_token_configured
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError(''); setSubmitting(true)
    try { const response = await api.start({ repository, branch: branch.trim() || null, modules: enabled, include_experimental: experimental }); onStarted(response.id) }
    catch (err) { setError(message(err)) }
    finally { setSubmitting(false) }
  }
  return <Dialog title="New repository scan" subtitle="Inspect the code. Understand the risk. Find the fix." onClose={onClose}><form onSubmit={event => void submit(event)} className="scan-form">
    {!ready && <div className="form-notice" role="status">{!connected ? <>Start the local engine with <code>python -m scanner.web</code> to enable scanning.</> : <>Set <code>GITHUB_TOKEN</code> in the backend environment and restart the engine. Credentials stay on your machine.</>}</div>}
    <label className="field-label" htmlFor="repository">GitHub repository<span>Required</span></label><div className="repository-input"><Github size={17} /><input id="repository" value={repository} onChange={e => setRepository(e.target.value)} placeholder="owner/repository or https://github.com/…" required maxLength={250} autoComplete="off" /></div>
    <label className="field-label" htmlFor="branch">Branch<span>Optional</span></label><input className="text-input" id="branch" value={branch} onChange={e => setBranch(e.target.value)} placeholder="Default branch" maxLength={250} />
    <fieldset><legend>Scan modules</legend><div className="module-options">{modules.map(m => <label key={m}><input type="checkbox" checked={enabled.includes(m)} onChange={e => setEnabled(e.target.checked ? [...enabled, m] : enabled.filter(value => value !== m))} /><span>{moduleNames[m]}<small>{m === 'ai' ? 'Prompts, secrets & models' : m === 'sast' ? 'Code security patterns' : m === 'sca' ? 'Packages & advisories' : 'MCP, tools & permissions'}</small></span></label>)}</div></fieldset>
    <label className="experimental-option"><input type="checkbox" checked={experimental} onChange={e => setExperimental(e.target.checked)} /><span>Include experimental rules<small>Broader coverage. Findings may need extra validation.</small></span></label>
    {error && <div className="error-banner" role="alert">{error}</div>}
    <div className="form-footer"><span><ShieldCheck size={13} /> Read-only analysis</span><button type="button" className="quiet-button" onClick={onClose}>Cancel</button><button className="primary-button" type="submit" disabled={!ready || submitting || enabled.length === 0 || !repository.trim()}>{submitting ? <LoaderCircle size={15} className="spin" /> : <Plus size={15} />}{submitting ? 'Starting…' : 'Start scan'}</button></div>
  </form></Dialog>
}

function FindingPanel({ finding, result, sample, onClose }: { finding: Finding; result: ScanResult; sample: boolean; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState('')
  async function copy() {
    try {
      await navigator.clipboard.writeText(finding.title + '\n' + finding.file_path + ':' + (finding.line_number ?? '') + '\nScope: ' + (finding.scope || 'application') + '\nEvidence: ' + (finding.evidence_kind || 'static pattern, unverified') + '\n\n' + finding.description + '\n\nRecommendation\n' + (finding.recommendation || 'No recommendation supplied.'))
      setCopied(true); setCopyError('')
    } catch { setCopyError('Could not copy. Select and copy the remediation text below.') }
  }
  return <Dialog title="Finding details" subtitle={sample ? 'Sample evidence · illustrative report' : result.repo_full_name} onClose={onClose} panel>
    <div className="detail-content"><div className="detail-labels"><span className={'severity-badge ' + finding.severity.toLowerCase()}><span className="severity-dot" />{severityName(finding.severity)}</span><span className={'status-tag ' + finding.status}>{finding.status}</span></div><h3 className="detail-title">{finding.title}</h3><p className="detail-description">{finding.description}</p>
      <div className="detail-location"><FileCode2 size={16} /><code>{finding.file_path}:{finding.line_number ?? '—'}</code>{!sample && <a href={sourceUrl(result, finding)} target="_blank" rel="noreferrer" aria-label="Open source on GitHub"><ArrowUpRight size={16} /></a>}</div>
      <div className="detail-section"><h4>Source evidence</h4><pre className="evidence-code">{finding.code_snippet || 'No source snippet was supplied for this finding.'}</pre></div>
      <div className="detail-section remediation"><div><h4>Recommended action</h4><button className="icon-button" aria-label="Copy remediation details" onClick={() => void copy()}>{copied ? <Check size={15} /> : <Copy size={15} />}</button></div><p>{finding.recommendation || 'Review the affected code and validate the finding before making a change.'}</p>{copied && <small role="status">Copied to clipboard.</small>}{copyError && <small role="alert">{copyError}</small>}</div>
      <dl className="finding-properties"><div><dt>Module</dt><dd>{moduleNames[finding.module] || finding.module}</dd></div><div><dt>Confidence</dt><dd>{finding.confidence}</dd></div><div><dt>Maturity</dt><dd>{finding.maturity}</dd></div><div><dt>Weakness</dt><dd>{finding.cwe || 'Not specified'}</dd></div><div><dt>Rule</dt><dd><code>{finding.rule_id || 'Not specified'}</code></dd></div><div className="fingerprint"><dt>Fingerprint</dt><dd><code>{finding.fingerprint || 'Not supplied'}</code></dd></div></dl>
      {finding.references.filter(url => /^https?:\/\//.test(url)).length > 0 && <div className="detail-section"><h4>References</h4>{finding.references.filter(url => /^https?:\/\//.test(url)).map(url => <a className="reference-link" key={url} href={url} target="_blank" rel="noreferrer">{url}<ArrowUpRight size={13} /></a>)}</div>}
      <div className="detail-section"><h4>Evidence classification</h4><p>{finding.evidence_kind || 'Static pattern; not runtime verified'} · Scope: {finding.scope || 'application'}</p><p>Severity source: {finding.severity_source || 'rule'}</p>{Boolean(finding.aliases?.length) && <p>Advisory identities: {finding.aliases?.join(', ')}</p>}{Boolean(finding.trace?.length) && <ol>{finding.trace?.map((step, index) => <li key={index}>{step.role}: <code>{step.file_path}:{step.line_number}</code></li>)}</ol>}</div><div className="detail-section"><h4>Category</h4><p>{finding.category}</p></div><div className="detail-note"><ShieldCheck size={16} /><p>Validate the evidence before opening an issue or pull request. Security findings may require private disclosure.</p></div>
    </div>
  </Dialog>
}
