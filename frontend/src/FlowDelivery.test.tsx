import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import App from './App'
import { api } from './api'
import type { ScanJob, ScanResult } from './api'
import backendReport from '../../tests/fixtures/flow-delivery-report.json'
import libraryReport from '../../tests/fixtures/library-boundary-report.json'
import obligationReport from '../../tests/fixtures/obligation-report.json'
import { readFileSync } from 'node:fs'

const generatedHtml = readFileSync('../tests/fixtures/flow-delivery-report.html', 'utf8')

it('shows all backend required-condition evidence in finding details and HTML', async () => {
  const user = userEvent.setup()
  const report = obligationReport as ScanResult
  const job: ScanJob = { id:'obligations',repository:report.repo_full_name,branch:'main',modules:['sast'],include_experimental:false,
    status:'completed',created_at:'2026-11-14T00:00:00Z',finished_at:null,error:null,result:report }
  vi.spyOn(api,'health').mockResolvedValue({ status:'ok',github_token_configured:true })
  vi.spyOn(api,'list').mockResolvedValue([job])
  vi.spyOn(api,'get').mockResolvedValue(job)
  render(<App />)
  await user.click(await screen.findByRole('button',{name:/obligations.*completed/}))
  for (const finding of report.findings.filter(f => f.obligation)) {
    await user.click(screen.getByRole('button',{name:finding.title}))
    expect(screen.getByText('Required security condition')).toBeInTheDocument()
    expect(screen.getAllByText(finding.obligation!.required).length).toBeGreaterThan(0)
    expect(screen.getAllByText(finding.obligation!.observed).length).toBeGreaterThan(0)
    for (const assumption of finding.obligation!.assumptions) expect(screen.getByText(assumption)).toBeInTheDocument()
    for (const location of finding.obligation!.related_locations || []) expect(screen.getAllByText(`${location.file_path}:${location.line_number}`).length).toBeGreaterThan(0)
    await user.click(screen.getByRole('button',{name:'Copy remediation details'}))
    expect(await navigator.clipboard.readText()).toContain(finding.obligation!.required)
    await user.keyboard('{Escape}')
  }
  const doc = document.implementation.createHTMLDocument('Obligation evidence')
  doc.documentElement.innerHTML = readFileSync('../tests/fixtures/obligation-report.html','utf8')
  new Function('document',doc.querySelector('script')!.textContent!)(doc)
  expect(doc.querySelectorAll('.finding-obligation')).toHaveLength(3)
  for (const f of report.findings.filter(f => f.obligation)) expect(doc.body.textContent).toContain(f.obligation!.required)
})

it('shows configured trust assumptions as advisory and retains only observed MCP associations', async () => {
  const user = userEvent.setup()
  const report = libraryReport as ScanResult
  const job: ScanJob = { id:'library-delivery',repository:report.repo_full_name,branch:'main',modules:['sast'],include_experimental:false,
    status:'completed',created_at:'2026-11-14T00:00:00Z',finished_at:null,error:null,result:report }
  vi.spyOn(api,'health').mockResolvedValue({ status:'ok',github_token_configured:true })
  vi.spyOn(api,'list').mockResolvedValue([job])
  vi.spyOn(api,'get').mockResolvedValue(job)
  render(<App />)
  await user.click(await screen.findByRole('button',{ name:/project.*completed/ }))
  const findings = screen.getAllByRole('button',{name:'Untrusted selection controls an invoked module attribute'})
  await user.click(findings[0])
  expect(screen.getByText(/Conditional on configured entrypoint trust boundary/)).toBeInTheDocument()
  expect(screen.getAllByText('advisory').length).toBeGreaterThan(0)
  expect(screen.getByText(/configured-flow · Scope: application/)).toBeInTheDocument()
  await user.keyboard('{Escape}')
  await user.click(screen.getByRole('tab',{name:/MCP links/}))
  expect(screen.getAllByRole('link',{name:/Untrusted selection controls an invoked module attribute/})).toHaveLength(1)
})

it('displays ASGI and archive flows, their traces and the runtime review notice', async () => {
  const user = userEvent.setup()
  const report = backendReport as ScanResult
  const job: ScanJob = { id:'flow-delivery',repository:report.repo_full_name,branch:'main',modules:['sast'],include_experimental:false,
    status:'completed',created_at:'2026-11-13T00:00:00Z',finished_at:null,error:null,result:report }
  vi.spyOn(api,'health').mockResolvedValue({ status:'ok',github_token_configured:true })
  vi.spyOn(api,'list').mockResolvedValue([job])
  vi.spyOn(api,'get').mockResolvedValue(job)
  render(<App />)
  await user.click(await screen.findByRole('button',{ name:/project.*completed/ }))
  expect(await screen.findByText('Showing 3 of 3 findings')).toBeInTheDocument()
  await user.click(screen.getByRole('button',{ name:'External input controls a filesystem path' }))
  expect(screen.getByText('CWE-22')).toBeInTheDocument()
  expect(screen.getAllByText('server.py:11').length).toBeGreaterThan(0)
  expect(screen.getAllByText('server.py:12').length).toBeGreaterThan(0)
  await user.keyboard('{Escape}')
  await user.click(screen.getByRole('button',{ name:'Archive extraction filter needs runtime/context review' }))
  expect(screen.getByText(/Python 3.14\+ changed the default to data/)).toBeInTheDocument()
  expect(screen.getAllByText('advisory').length).toBeGreaterThan(0)
  await user.keyboard('{Escape}')
  await user.click(screen.getByRole('tab',{ name:/MCP links/ }))
  expect(screen.getByRole('link',{ name:'Untrusted archive reaches fully-trusted extraction · server.py:15' })).toBeInTheDocument()
  expect(screen.getByRole('link',{ name:'External input controls a filesystem path · server.py:12' })).toBeInTheDocument()
})

it('renders evidence visibly in the backend-generated standalone HTML export', () => {
  const reportDocument = document.implementation.createHTMLDocument('Original report fixture')
  reportDocument.documentElement.innerHTML = generatedHtml
  const script = reportDocument.querySelector('script')?.textContent
  expect(script).toBeTruthy()
  // Execute only our trusted report renderer; scanned fixture source remains JSON/text.
  new Function('document', script!)(reportDocument)
  const evidence = reportDocument.querySelectorAll('.finding-evidence')
  expect(evidence).toHaveLength(3)
  expect(evidence[0].textContent).toContain('static-flow')
  expect(evidence[0].textContent).toContain('source: server.py:11')
  expect(evidence[0].textContent).toContain('sink: server.py:12')
  expect(evidence[2].textContent).toContain('coverage-notice')
  expect(evidence[2].textContent).toContain('Maturity: advisory')
})
