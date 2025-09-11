import { render, screen } from '@testing-library/react'
import App from './App'

it('renders Connect screen text', () => {
  render(<App />)
  expect(screen.getByText('AI Proxy Logs UI')).toBeInTheDocument()
  expect(screen.getByText(/Connect to your Logs API/)).toBeInTheDocument()
})


