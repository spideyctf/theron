import {render, screen} from '@testing-library/react'
import {expect, it} from 'vitest'
import {formatScanTimestamp, ScanDetails} from './ReportDetails'
import {sampleReport} from './sample'
import type {ScanJob} from './api'

it('converts UTC dates across midnight into India local time', () => {
  const created = formatScanTimestamp('2026-11-16T18:39:58.410924+00:00','Asia/Kolkata')
  const finished = formatScanTimestamp('2026-11-16T18:40:16.178944+00:00','Asia/Kolkata')
  expect(created).toMatch(/17/)
  expect(created).toMatch(/12:09:58/)
  expect(finished).toMatch(/12:10:16/)
  expect(created).toMatch(/IST|GMT\+5:30/)
  expect(formatScanTimestamp('invalid')).toBe('Unavailable')
})

it('renders readable dates with original timestamps retained and handles unfinished jobs', () => {
  const job: ScanJob={id:'time',repository:'owner/repo',branch:'main',modules:['sast'],include_experimental:false,
    status:'running',created_at:'2026-11-16T18:39:58.410924+00:00',finished_at:null,error:null}
  const {container,rerender}=render(<ScanDetails result={sampleReport} job={job} sample={false} />)
  expect(container.querySelector('time')?.dateTime).toBe(job.created_at)
  expect(container.querySelector('time')?.textContent).not.toContain('T18:39')
  expect(screen.getByText('Not finished')).toBeInTheDocument()
  rerender(<ScanDetails result={sampleReport} job={{...job,status:'completed',finished_at:'2026-11-16T18:40:16.178944+00:00'}} sample={false} />)
  expect(container.querySelectorAll('time')).toHaveLength(2)
  expect(container.querySelectorAll('time')[1].dateTime).toBe('2026-11-16T18:40:16.178944+00:00')
})
