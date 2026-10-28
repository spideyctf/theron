export const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
export const modules = ['ai', 'sast', 'sca', 'agentic'] as const
export type Severity = typeof severities[number]
export type Module = typeof modules[number]
export interface Finding {
  title: string; severity: Severity; category: string; module: string; description: string
  file_path: string; line_number: number | null; code_snippet: string | null
  recommendation: string | null; cwe: string | null; confidence: string; rule_id: string | null
  references: string[]; fingerprint: string | null; maturity: string; status: string
  scope?: string; evidence_kind?: string; aliases?: string[]; severity_source?: string
  trace?: { role: string; file_path: string; line_number: number }[]
}
export interface ScanResult {
  repo_full_name: string; branch: string; findings: Finding[]; files_scanned: number
  modules_run: string[]; sbom: unknown; scan_duration_seconds: number; project_profile: unknown
  context_findings?: Finding[]
  commit_sha?: string | null
  summary: { repo: string; branch: string; files_scanned: number; total_findings: number
    by_severity: Partial<Record<Severity, number>>; modules_run: string[]; scan_duration_seconds: number }
}
export interface ScanJob {
  id: string; repository: string; branch: string | null; modules: string[]; include_experimental: boolean
  status: 'queued' | 'running' | 'completed' | 'failed'; created_at: string; finished_at: string | null
  error: string | null; result?: ScanResult | null
}
export interface ScanInput { repository: string; branch: string | null; modules: string[]; include_experimental: boolean }
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
export function sourceUrl(result: ScanResult, finding: Finding): string {
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

