import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import { Correlations } from './ReportDetails'
import App from './App'
import { api } from './api'
import type { ScanJob, ScanResult } from './api'
import backendReport from '../../tests/fixtures/correlation-report.json'

const report = backendReport as ScanResult

it('renders backend groups, classifications, member references and every source/sink location', () => {
  render(<Correlations result={report} />)
  const group = report.correlation_groups![0]
  const region = screen.getByRole('region', { name:group.title })
  expect(within(region).getByText(group.id)).toBeInTheDocument()
  expect(within(region).getByText('declares entrypoint · inferred')).toBeInTheDocument()
  expect(within(region).getByText('entrypoint contains flow · observed')).toBeInTheDocument()
  expect(within(region).getByText(group.finding_fingerprints[0])).toBeInTheDocument()
  expect(within(region).getAllByRole('link', { name:'server.py:1' })).toHaveLength(2)
  expect(within(region).getByRole('link', { name:report.findings[0].title+' · server.py:1' })).toHaveAttribute('href',expect.stringContaining('/blob/'+'a'.repeat(40)+'/server.py#L1'))
  group.limitations.forEach(limit => expect(within(region).getByText(limit)).toBeInTheDocument())
  expect(screen.getByText('workspace binding inferred')).toBeInTheDocument()
})

it('distinguishes disabled, old and unresolved reports without implying safety', () => {
  const { rerender } = render(<Correlations result={{ ...report,correlation_enabled:false }} />)
  expect(screen.getByRole('heading',{ name:'MCP links disabled' })).toBeInTheDocument()
  rerender(<Correlations result={{ ...report,correlation_enabled:undefined }} />)
  expect(screen.getByRole('heading',{ name:'MCP links unavailable' })).toBeInTheDocument()
  rerender(<Correlations result={{ ...report,correlation_groups:[],correlation_resolutions:[{
    config_file:'.mcp.json',pointer:'/mcpServers/local',status:'unresolved',reason:'unresolved_working_directory',
    entrypoint:null,classification:'unknown',scope:'example',group_ids:[],
  }] }} />)
  expect(screen.getByText('unresolved working directory')).toBeInTheDocument()
  expect(screen.getByText(/does not establish safety/)).toBeInTheDocument()
  expect(screen.getByText('unresolved · unknown')).toBeInTheDocument()
})

it('opens correlation evidence from the live report tab', async () => {
  vi.spyOn(api,'health').mockResolvedValue({ status:'ok',github_token_configured:true })
  const job: ScanJob = { id:'correlated',repository:'owner/project',branch:'main',modules:['sast'],include_experimental:false,
    status:'completed',created_at:'2026-11-13T00:00:00Z',finished_at:'2026-11-13T00:00:01Z',error:null,result:report }
  vi.spyOn(api,'list').mockResolvedValue([job])
  vi.spyOn(api,'get').mockResolvedValue(job)
  const user = userEvent.setup()
  render(<App />)
  await user.click(await screen.findByRole('button',{ name:/project.*completed/ }))
  await user.click(await screen.findByRole('tab',{ name:'MCP links (1)' }))
  expect(await screen.findByRole('heading',{ name:'MCP configuration-to-code links' })).toBeInTheDocument()
  expect(screen.getByText(report.correlation_groups![0].id)).toBeInTheDocument()
  expect(screen.getByText(/Groups reference existing findings and add no vulnerability count/)).toBeInTheDocument()
  await user.click(screen.getByRole('button',{ name:`Inspect original finding: ${report.findings[0].title}` }))
  expect(screen.getByRole('dialog',{ name:'Finding details' })).toBeInTheDocument()
  expect(within(screen.getByRole('dialog')).getByText(report.findings[0].fingerprint!)).toBeInTheDocument()
})
