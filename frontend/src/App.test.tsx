import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { api, filterFindings, sourceUrl } from './api'
import type { ScanJob, ScanResult } from './api'
import { sampleReport } from './sample'

beforeEach(() => {
  vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok', github_token_configured: false })
  vi.spyOn(api, 'list').mockResolvedValue([])
})

describe('workspace', () => {
  it('combines filters and clears an empty result', async () => {
    const user = userEvent.setup()
    render(<App />)
    expect(screen.getByText('SAMPLE REPORT')).toBeInTheDocument()
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter by severity' }), 'HIGH')
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter by module' }), 'agentic')
    expect(screen.getByRole('button', { name: 'MCP server uses insecure transport' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Unsafe model deserialization' })).not.toBeInTheDocument()
    await user.type(screen.getByRole('textbox', { name: 'Search findings' }), 'no match')
    expect(screen.getByText('No findings match these filters')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(screen.getByText('Showing 8 of 8 findings')).toBeInTheDocument()
  })

  it('opens evidence, copies remediation, and closes using Escape', async () => {
    const user = userEvent.setup()
    render(<App />)
    await user.click(screen.getByRole('button', { name: 'LLM output reaches code execution' }))
    const dialog = screen.getByRole('dialog', { name: 'Finding details' })
    expect(within(dialog).getByText('Source evidence')).toBeInTheDocument()
    expect(within(dialog).getByText('sample-0001')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Copy remediation details' }))
    expect(await within(dialog).findByText('Copied to clipboard.')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('explains missing token and preserves input while editing the form', async () => {
    const user = userEvent.setup()
    render(<App />)
    await screen.findByText('Local engine connected')
    await user.click(screen.getAllByRole('button', { name: 'New scan' })[1])
    const dialog = screen.getByRole('dialog', { name: 'New repository scan' })
    await user.type(within(dialog).getByRole('textbox', { name: /GitHub repository/ }), 'owner/repo')
    expect(within(dialog).getByRole('textbox', { name: /GitHub repository/ })).toHaveValue('owner/repo')
    expect(within(dialog).getByRole('button', { name: 'Start scan' })).toBeDisabled()
    expect(within(dialog).getByText(/Credentials stay on your machine/)).toBeInTheDocument()
  })

  it('submits a live scan and renders an empty completed report', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'health').mockResolvedValue({ status: 'ok', github_token_configured: true })
    vi.spyOn(api, 'start').mockResolvedValue({ id: 'live' })
    const completed: ScanJob = { id: 'live', repository: 'owner/repo', branch: 'main', modules: ['ai'], include_experimental: false, status: 'completed', created_at: new Date().toISOString(), finished_at: null, error: null,
      result: { ...sampleReport, repo_full_name: 'owner/repo', findings: [], files_scanned: 2 } }
    vi.spyOn(api, 'get').mockResolvedValue(completed)
    render(<App />)
    await screen.findByText('Local engine connected')
    await user.click(screen.getAllByRole('button', { name: 'New scan' })[1])
    const dialog = screen.getByRole('dialog', { name: 'New repository scan' })
    await user.type(within(dialog).getByRole('textbox', { name: /GitHub repository/ }), 'owner/repo')
    await user.click(within(dialog).getByRole('button', { name: 'Start scan' }))
    await screen.findByText('No findings reported')
    expect(api.start).toHaveBeenCalledWith({ repository: 'owner/repo', branch: null, modules: ['ai', 'sast', 'sca', 'agentic'], include_experimental: false })
    expect(screen.queryByText('SAMPLE REPORT')).not.toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: /SARIF/ })).not.toBeDisabled())
  })

  it('uses new/existing status and safely constructs source links', () => {
    expect(filterFindings(sampleReport.findings, '', 'all', 'all', 'existing')).toHaveLength(2)
    expect(sourceUrl({ ...sampleReport, branch: 'fix/agents' }, sampleReport.findings[0])).toContain('/blob/fix%2Fagents/agents/research.py#L42')
  })

  it('shows live findings, coverage, SBOM, profile and job data from the same report', async () => {
    const user = userEvent.setup()
    const report: ScanResult = {
      ...sampleReport,
      repo_full_name: 'owner/audit',
      findings: [...sampleReport.findings, { ...sampleReport.findings[0], title: 'File analysis skipped', module: 'coverage', severity: 'INFO', fingerprint: 'coverage-1', description: 'The file exceeds the 500 KB analysis limit.', maturity: 'stable' }],
      sbom: { bomFormat: 'CycloneDX', specVersion: '1.5', metadata: { timestamp: '2026-10-28T10:00:00Z' }, components: [
        { name: 'exact-package', version: '1.2.3', type: 'library', purl: 'pkg:pypi/exact-package@1.2.3', properties: [{ name: 'source_file', value: 'requirements.txt' }] },
        { name: 'ranged-package', type: 'library', purl: 'pkg:npm/ranged-package', properties: [{ name: 'theron:version_status', value: 'unresolved' }, { name: 'theron:declared_version', value: '^2.0' }] },
      ] },
      project_profile: { primary_language: 'python', languages: ['python', 'typescript'], has_mcp_servers: true, mcp_config_files: ['.mcp.json'], dependency_manifests: ['requirements.txt'], ai_frameworks: [{ name: 'openai', confidence: 'high', evidence: ['Dependency: openai in requirements.txt'] }] },
    }
    const live: ScanJob = { id: 'audit-job', repository: 'owner/audit', branch: 'main', status: 'completed', modules: ['ai', 'sast', 'sca', 'agentic'], include_experimental: true, created_at: '2026-10-28T10:00:00Z', finished_at: '2026-10-28T10:01:00Z', error: null, result: report }
    vi.spyOn(api, 'list').mockResolvedValue([live])
    vi.spyOn(api, 'get').mockResolvedValue(live)
    render(<App />)
    await user.click(await screen.findByRole('button', { name: /audit.*completed/ }))
    await screen.findByText('Showing 9 of 9 findings')
    expect(screen.getAllByRole('row')).toHaveLength(report.findings.length + 1)
    expect(screen.getByText(/1 informational notices/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Review notices' }))
    expect(screen.getByRole('button', { name: 'File analysis skipped' })).toBeInTheDocument()
    expect(screen.getByText('Showing 1 of 9 findings')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: 'Dependencies / SBOM' }))
    expect(screen.getByText(/2 components · 1 unresolved versions/)).toBeInTheDocument()
    expect(screen.getByText('exact-package')).toBeInTheDocument()
    expect(screen.getByText('1.2.3')).toBeInTheDocument()
    expect(screen.getByText('Declared: ^2.0')).toBeInTheDocument()
    await user.type(screen.getByRole('textbox', { name: 'Search dependencies' }), 'ranged-package')
    expect(screen.queryByText('exact-package')).not.toBeInTheDocument()
    expect(screen.getByText('Showing 1 of 2 components.')).toBeInTheDocument()
    await user.click(screen.getByText('Complete SBOM data, including metadata and component properties'))
    expect(screen.getByText(/"timestamp": "2026-10-28T10:00:00Z"/)).toBeVisible()

    await user.click(screen.getByRole('tab', { name: 'Project profile' }))
    expect(screen.getByText('primary language')).toBeInTheDocument()
    expect(screen.getByText('python', { exact: true })).toBeInTheDocument()
    expect(screen.getByText(/Dependency: openai in requirements.txt/)).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: 'Scan details' }))
    expect(screen.getByText('audit-job')).toBeInTheDocument()
    expect(screen.getByText('Enabled — review candidates')).toBeInTheDocument()
    expect(screen.getByText('2026-10-28T10:01:00Z', { exact: true })).toBeInTheDocument()
    await user.click(screen.getByText('Complete report data', { exact: true }))
    expect(screen.getByText(/"repo_full_name": "owner\/audit"/)).toBeVisible()
  })

  it('explains absent SBOM and project profile rather than inventing data', async () => {
    const user = userEvent.setup()
    render(<App />)
    await user.click(screen.getByRole('tab', { name: 'Dependencies / SBOM' }))
    expect(screen.getByText('No SBOM available')).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: 'Project profile' }))
    expect(screen.getByText('No project profile supplied')).toBeInTheDocument()
  })
})

