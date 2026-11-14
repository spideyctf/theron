import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import { Correlations, Dependencies } from './ReportDetails'
import App from './App'
import { api } from './api'
import type { ScanJob, ScanResult } from './api'
import backendReport from '../../tests/fixtures/correlation-report.json'
import toolReport from '../../tests/fixtures/tool-correlation-report.json'

const report = backendReport as ScanResult

it('shows package entrypoint claims and source hashes with runtime limits', () => {
  const value: ScanResult = {...report, correlation_groups: [], correlation_resolutions: [{
    config_file: '.mcp.json', pointer: '/mcpServers/demo', status: 'resolved', reason: 'package_entrypoint_inferred',
    entrypoint: 'server.py', classification: 'inferred', scope: 'application', group_ids: [],
    package_entrypoint: {basis: 'local_project_script', package: 'demo', command: 'demo', object_reference: 'server:main',
      callable_file: 'server.py', callable_line: 10, installation_verified: false, startup_verified: false,
      source_text_sha256: {'pyproject.toml': 'abc123'}},
  }]}
  render(<Correlations result={value} />)
  expect(screen.getByText('Package entrypoint evidence')).toBeInTheDocument()
  expect(screen.getByText(/installation and startup unverified/)).toBeInTheDocument()
  expect(within(screen.getByText('Package entrypoint evidence').parentElement!).getByText(/abc123/)).toBeInTheDocument()
})

it('distinguishes locked inventory versions from verified installation', () => {
  render(<Dependencies result={{...report, sbom: {components: [{name: 'demo', version: '1.0',
    properties: [{name: 'source_file', value: 'uv.lock'}, {name: 'theron:version_basis',
      value: 'locked inventory; installation and environment selection unverified'}]}]}}} />)
  expect(screen.getByText('locked inventory; installation and environment selection unverified')).toBeInTheDocument()
  expect(screen.getByText('uv.lock')).toBeInTheDocument()
})

it('renders tool symbols, dependency attribution and snapshot provenance from the backend fixture', () => {
  const result=toolReport as ScanResult
  render(<Correlations result={result} />)
  const region=screen.getByRole('region',{name:'Declared MCP tool: inspect_text'})
  expect(within(region).getByText('calls imported api · inferred')).toBeInTheDocument()
  expect(within(region).getByText(/helpers.parse.*yaml.load/)).toBeInTheDocument()
  expect(within(region).getByText(/yaml.load.*PyYAML@1.0.0/)).toBeInTheDocument()
  expect(within(region).getByText('Evidence basis: distribution record claim')).toBeInTheDocument()
  const provenance=result.correlation_groups!.find(g=>g.id.startsWith('mcp-tool-'))!.relationships.find(e=>e.kind==='declared_version_matches_osv_advisory')!.provenance!
  expect(within(region).getByText((_,element)=>element?.tagName==='PRE' && element.textContent===JSON.stringify(provenance,null,2))).toBeInTheDocument()
  expect(within(region).getAllByRole('link',{name:'helpers.py:3'}).length).toBeGreaterThan(0)
  result.correlation_groups!.find(g=>g.id.startsWith('mcp-tool-'))!.limitations.forEach(limit=>expect(within(region).getByText(limit)).toBeInTheDocument())
})

it('shows unresolved tool and call-path reasons separately from findings', () => {
  const result=structuredClone(toolReport) as ScanResult
  result.correlation_groups!.find(g=>g.id.startsWith('mcp-tool-'))!.resolution_notes=[{reason:'handler_call_depth_reached',file_path:'helpers.py',line_number:3}]
  result.correlation_resolutions![0].tool_resolution_notes=[{reason:'unsupported_tool_decorator',file_path:'server.py',line_number:4}]
  render(<Correlations result={result} />)
  expect(screen.getByText('handler call depth reached · helpers.py:3')).toBeInTheDocument()
  expect(screen.getByText('Tool resolution: unsupported tool decorator · server.py:4')).toBeInTheDocument()
})

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
