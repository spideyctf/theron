import { useState } from 'react'
import { downloadBlob } from './api'
import type { ScanJob, ScanResult } from './api'

type Component = { name?: string; version?: string; purl?: string; type?: string; 'bom-ref'?: string; properties?: { name: string; value: string }[] }
type Bom = { bomFormat?: string; specVersion?: string; components?: Component[] }
const pretty = (value: unknown) => JSON.stringify(value, null, 2)

export function Dependencies({ result }: { result: ScanResult }) {
  const [search, setSearch] = useState('')
  const bom = result.sbom as Bom | null
  if (!bom) return <div className="report-empty"><h3>No SBOM available</h3><p>{result.modules_run.includes('sca') ? 'The scanner did not supply a dependency inventory.' : 'Run the Dependencies (SCA) module to generate an SBOM.'}</p></div>
  const components = bom.components || []
  const filtered = components.filter(component => pretty(component).toLowerCase().includes(search.trim().toLowerCase()))
  const unresolved = components.filter(component => !component.version || component.properties?.some(property => property.name === 'theron:version_status' && property.value === 'unresolved')).length
  return <div className="report-content">
    <div className="report-section-heading"><div><h3>Dependency inventory</h3><p>{components.length} components · {unresolved} unresolved versions · {bom.bomFormat || 'SBOM'} {bom.specVersion || ''}</p></div><button className="quiet-button" onClick={() => downloadBlob(pretty(result.sbom), 'theron_sbom.json')}>Download SBOM</button></div>
    <p className="report-note">This inventory comes from supported manifests and lockfiles. Unresolved versions were not checked as installed versions. Advisory findings are listed under Findings; a component without an alert is not a security guarantee.</p>
    <label className="report-search">Search dependencies<input className="text-input" value={search} onChange={event => setSearch(event.target.value)} placeholder="Package, version, source or package URL" /></label>
    <div className="table-scroll"><table className="inventory-table"><thead><tr><th>Package</th><th>Version</th><th>Source</th><th>Package URL</th></tr></thead><tbody>{filtered.map((component, index) => {
      const source = component.properties?.filter(property => property.name === 'source_file').map(property => property.value).join(', ')
      const declared = component.properties?.find(property => property.name === 'theron:declared_version')?.value
      return <tr key={component['bom-ref'] || component.purl || index}><td><strong>{component.name || 'Unnamed component'}</strong><small>{component.type || 'Unspecified type'}</small></td><td>{component.version || 'Unresolved'}{!component.version && declared && <small>Declared: {declared}</small>}</td><td>{source || 'Not supplied'}</td><td><code>{component.purl || 'Not supplied'}</code></td></tr>
    })}</tbody></table></div>
    {!filtered.length && <p role="status">{components.length ? 'No dependencies match this search.' : 'No supported dependencies were parsed. Review the informational findings for coverage limits.'}</p>}
    <p className="report-note">Showing {filtered.length} of {components.length} components.</p>
    <details className="raw-data"><summary>Complete SBOM data, including metadata and component properties</summary><pre>{pretty(result.sbom)}</pre></details>
  </div>
}

export function ProjectDetails({ result }: { result: ScanResult }) {
  const profile = result.project_profile as Record<string, unknown> | null
  if (!profile) return <div className="report-empty"><h3>No project profile supplied</h3><p>This report predates profile export, or the scanner did not provide one. Run a new scan to populate it.</p></div>
  return <div className="report-content"><h3>Project profile</h3><p className="report-note">Framework detections are static indicators, including matches in examples and tests. They do not prove a framework is deployed.</p><dl className="profile-grid">{Object.entries(profile).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{typeof value === 'boolean' ? (value ? 'Yes' : 'No') : Array.isArray(value) ? (value.length ? <pre>{pretty(value)}</pre> : 'None detected') : typeof value === 'object' && value !== null ? <pre>{pretty(value)}</pre> : String(value ?? 'Not supplied')}</dd></div>)}</dl></div>
}

export function ScanDetails({ result, job, sample }: { result: ScanResult; job: ScanJob | null; sample: boolean }) {
  const notices = result.findings.filter(finding => finding.severity === 'INFO')
  return <div className="report-content"><h3>Scan details</h3><dl className="profile-grid">
    <div><dt>Repository</dt><dd>{result.repo_full_name}</dd></div><div><dt>Branch</dt><dd>{result.branch}</dd></div>
    <div><dt>Files analyzed</dt><dd>{result.files_scanned}</dd></div><div><dt>Duration</dt><dd>{result.scan_duration_seconds} seconds</dd></div>
    <div><dt>Modules completed</dt><dd>{result.modules_run.join(', ') || 'None'}</dd></div><div><dt>Informational notices</dt><dd>{notices.length}</dd></div>
    <div><dt>Report origin</dt><dd>{sample ? 'Illustrative sample data' : 'Live scan'}</dd></div>
    {job && <><div><dt>Scan ID</dt><dd><code>{job.id}</code></dd></div><div><dt>Status</dt><dd>{job.status}</dd></div><div><dt>Modules requested</dt><dd>{job.modules.join(', ')}</dd></div><div><dt>Experimental rules</dt><dd>{job.include_experimental ? 'Enabled — review candidates' : 'Disabled'}</dd></div><div><dt>Created at</dt><dd>{job.created_at}</dd></div><div><dt>Finished at</dt><dd>{job.finished_at || 'Not finished'}</dd></div></>}
  </dl><p className="report-note">An empty findings list does not prove a project is secure. Review informational notices for skipped files, unresolved versions and unavailable advisory lookups. History resets when the backend restarts.</p>
    {job && <details className="raw-data"><summary>Complete job metadata</summary><pre>{pretty(Object.fromEntries(Object.entries(job).filter(([key]) => key !== 'result')))}</pre></details>}
    <details className="raw-data"><summary>Complete report data</summary><pre>{pretty(result)}</pre></details>
  </div>
}
