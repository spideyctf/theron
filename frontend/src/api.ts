export const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
export const modules = ['ai', 'sast', 'sca', 'agentic'] as const
export type Severity = typeof severities[number]
export type Module = typeof modules[number]
export interface ApplicationReview {
  status: string; attribution_basis: string; imports_observed: number; calls_observed: number
  imports: {file_path: string; line_number: number; symbol: string; scope: string}[]
  calls: {file_path: string; line_number: number; symbol: string; scope: string}[]
  affected_behavior_verified: boolean; vulnerability_confirmed: boolean; limitations: string[]
  source_text_sha256: Record<string,string>; coverage: {python_files: number; parsed: number; parse_failures: string[]; file_limit: number; truncated: boolean}
}
export interface Finding {
  title: string; severity: Severity; category: string; module: string; description: string
  file_path: string; line_number: number | null; code_snippet: string | null
  recommendation: string | null; cwe: string | null; confidence: string; rule_id: string | null
  references: string[]; fingerprint: string | null; maturity: string; status: string
  scope?: string; evidence_kind?: string; aliases?: string[]; severity_source?: string
  trace?: { role: string; file_path: string; line_number: number }[]
  obligation?: { domain: string; required: string; observed: string; assumptions: string[]
    action: { file_path: string; line_number: number }
    related_locations?: { role: string; file_path: string; line_number: number; matches_returned_object?: boolean; matches_subject?: boolean }[] }
  dependency?: { package: string; version: string; ecosystem: string; manifest: string; provider: string
    advisory_ids: string[]; cwes: string[]; fixed_versions: string[]; queried_at: string; matching: string
    lock_provenance?: { format: string; source_text_sha256: string; installation_verified: boolean; environment_selected: boolean }
    application_review?: ApplicationReview }
}
export interface ScanResult {
  repo_full_name: string; branch: string; findings: Finding[]; files_scanned: number
  modules_run: string[]; sbom: unknown; scan_duration_seconds: number; project_profile: unknown
  context_findings?: Finding[]
  commit_sha?: string | null
  correlation_enabled?: boolean
  correlation_groups?: CorrelationGroup[]
  correlation_resolutions?: CorrelationResolution[]
  summary: { repo: string; branch: string; files_scanned: number; total_findings: number
    by_severity: Partial<Record<Severity, number>>; modules_run: string[]; scan_duration_seconds: number }
}
export interface EvidenceLocation { file_path: string; line_number?: number; pointer?: string; role?: string }
export interface CorrelationEndpoint { kind: string; file_path?: string; pointer?: string; fingerprint?: string
  symbol?: string; line_number?: number; package?: string; version?: string }
export interface CorrelationGroup {
  id: string; title: string; scope: string; classification: string; maturity: string
  finding_fingerprints: string[]; limitations: string[]
  resolution_notes?: { reason: string; file_path: string; line_number?: number }[]
  relationships: { kind: string; source: CorrelationEndpoint; target: CorrelationEndpoint; classification: string
    evidence: EvidenceLocation[]; confidence?: string; maturity?: string; basis?: string
    provenance?: { commit_sha: string | null; source_text_sha256: Record<string,string>; osv_queried_at?: string | null
      advisory_ids?: string[]; advisory_record_sha256?: string | null } }[]
}
export interface CorrelationResolution {
  config_file: string; pointer: string; status: string; reason: string; entrypoint: string | null
  classification: string; scope: string; group_ids: string[]
  tool_resolution_notes?: { reason: string; file_path: string; line_number?: number }[]
  package_entrypoint?: { basis: string; package: string; command: string; object_reference: string
    callable_file: string; callable_line: number; installation_verified: boolean; startup_verified: boolean
    source_text_sha256: Record<string,string>; floating_request?: boolean; candidate_version?: string }
  deployment_binding?: { basis: string; kind: string; reason: string; source_text_sha256: Record<string,string>
    runtime_verified: boolean; remote_identity_verified: boolean }
}
export interface ScanJob {
  id: string; repository: string; branch: string | null; modules: string[]; include_experimental: boolean
  status: 'queued' | 'running' | 'completed' | 'failed'; created_at: string; finished_at: string | null
  error: string | null; result?: ScanResult | null
  correlation_enabled?: boolean
}
export interface AnalysisEntrypoint { file: string; function: string; parameter: string; reason: string; type?: 'bs4.element.Tag' }
export interface ScanInput { repository: string; branch: string | null; modules: string[]; include_experimental: boolean; correlation_enabled?: boolean; analysis_entrypoints?: AnalysisEntrypoint[]
  mcp_bindings?: {config_file: string; pointer: string; entrypoint: string; config_sha256: string; entrypoint_sha256: string
    kind: 'http' | 'absolute-python'; reason: string}[] }
export interface Health { status: string; github_token_configured: boolean }

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, options)
  if (!response.ok) {
    const data = await response.json().catch(() => ({}))
    throw new Error(typeof data.detail === 'string' ? data.detail : 'Request failed. Check the backend and try again.')
  }
  return response.json() as Promise<T>
}
export const api = {
  health: () => request<Health>('/api/health'),
  list: () => request<ScanJob[]>('/api/scans'),
  get: (id: string) => request<ScanJob>('/api/scans/' + encodeURIComponent(id)),
  start: (input: ScanInput) => request<{ id: string }>('/api/scans', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input),
  }),
}
export function sourceUrl(result: ScanResult, finding: Pick<Finding, 'file_path' | 'line_number'>): string {
  const path = finding.file_path.replaceAll('\\', '/').split('/').map(encodeURIComponent).join('/')
  return 'https://github.com/' + result.repo_full_name + '/blob/' + encodeURIComponent(result.commit_sha || result.branch) + '/' + path + (finding.line_number ? '#L' + finding.line_number : '')
}
export function filterFindings(findings: Finding[], search: string, severity: string, module: string, status: string) {
  const term = search.trim().toLowerCase()
  return findings.filter(f => (!term || [f.title, f.file_path, f.rule_id, f.category].some(v => v?.toLowerCase().includes(term)))
    && (severity === 'all' || f.severity === severity)
    && (module === 'all' || f.module === module)
    && (status === 'all' || f.status === status))
}
export function downloadBlob(content: string, filename: string) {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/json' }))
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

