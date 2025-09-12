import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import JsonViewer from './JsonViewer'

describe('JsonViewer', () => {
  it('renders null value', () => {
    render(<JsonViewer value={null} />)
    expect(screen.getByText('null')).toBeInTheDocument()
  })

  it('renders string value', () => {
    render(<JsonViewer value="test" />)
    expect(screen.getByText('"test"')).toBeInTheDocument()
  })

  it('renders number value', () => {
    render(<JsonViewer value={42} />)
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('renders boolean value true', () => {
    render(<JsonViewer value={true} />)
    expect(screen.getByText('true')).toBeInTheDocument()
  })

  it('renders boolean value false', () => {
    render(<JsonViewer value={false} />)
    expect(screen.getByText('false')).toBeInTheDocument()
  })

  it('renders fallback for other primitives', () => {
    render(<JsonViewer value={undefined} />)
    expect(screen.getByText('undefined')).toBeInTheDocument()
  })

  it('renders collapsed object and expands', () => {
    const obj = { a: 1, b: 'test' }
    render(<JsonViewer value={obj} collapseThreshold={0} />) // Force collapse
    expect(screen.getByText('Object')).toBeInTheDocument()
    expect(screen.queryByText('a:')).not.toBeInTheDocument()

    fireEvent.click(screen.getByLabelText('toggle-node'))
    expect(screen.getByText('a:')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('b:')).toBeInTheDocument()
    expect(screen.getByText('"test"')).toBeInTheDocument()
  })

  it('renders collapsed array and expands', () => {
    const arr = [1, 'test']
    render(<JsonViewer value={arr} collapseThreshold={0} />) // Force collapse
    expect(screen.getByText('Array(2)')).toBeInTheDocument()
    expect(screen.queryByText('0:')).not.toBeInTheDocument()

    fireEvent.click(screen.getByLabelText('toggle-node'))
    expect(screen.getByText('0:')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('1:')).toBeInTheDocument()
    expect(screen.getByText('"test"')).toBeInTheDocument()
  })

  it('copies JSON on button click - success', async () => {
    const data = { a: 1 }
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })

    render(<JsonViewer value={data} />)
    fireEvent.click(screen.getByLabelText('copy-json'))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(JSON.stringify(data, null, 2)))
  })

  it('handles copy error gracefully', async () => {
    const data = { a: 1 }
    const writeText = vi.fn().mockRejectedValue(new Error('Permission denied'))
    vi.stubGlobal('navigator', { clipboard: { writeText } })

    render(<JsonViewer value={data} />)
    fireEvent.click(screen.getByLabelText('copy-json'))
    await waitFor(() => expect(writeText).toHaveBeenCalled())
    // No crash, just coverage for catch block
  })

  it('renders label and top-level copy button', () => {
    render(<JsonViewer value={{}} label="Test Label" />)
    expect(screen.getByText('Test Label')).toBeInTheDocument()
    expect(screen.getAllByLabelText('copy-json')).toHaveLength(2)
  })

  it('auto-expands short objects', () => {
    const obj = { a: 1 }
    render(<JsonViewer value={obj} collapseThreshold={100} />) // Preview short
    expect(screen.getByText('a:')).toBeInTheDocument() // Auto-expanded
  })

  it('collapses long strings by default', () => {
    const longStr = 'x'.repeat(300)
    render(<JsonViewer value={{ long: longStr }} collapseThreshold={256} />)
    expect(screen.queryByText(longStr)).not.toBeInTheDocument() // Collapsed, string not shown
    fireEvent.click(screen.getByLabelText('toggle-node'))
    expect(screen.getByText(`"${longStr}"`)).toBeInTheDocument() // Expanded, matches quoted string
  })

  it('handles non-serializable values in collapse check', () => {
    const bad = { toJSON() { throw new Error('bad') } }
    render(<JsonViewer value={bad} />)
    // stringify throws, catch '[object Object]', short -> auto-open
    expect(screen.getByText('Object')).toBeInTheDocument()
    // Auto-expanded, empty since no entries
    expect(screen.queryByText('big:')).not.toBeInTheDocument() // No properties
  })
})
