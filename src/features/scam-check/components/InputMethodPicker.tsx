import type { InputMode } from '../analysis/types'

const modes: { id: InputMode; label: string; detail: string }[] = [
  { id: 'message', label: 'Message', detail: 'SMS, chat, or email' },
  { id: 'url', label: 'Website link', detail: 'One web address' },
  { id: 'screenshot', label: 'Screenshot', detail: 'An image of a message' },
]

interface InputMethodPickerProps {
  value: InputMode
  onChange: (mode: InputMode) => void
  disabled: boolean
}

export function InputMethodPicker({ value, onChange, disabled }: InputMethodPickerProps) {
  return (
    <div className="input-mode-list" role="group" aria-label="Choose what you want to check">
      {modes.map((mode, index) => (
        <button
          aria-pressed={value === mode.id}
          className={`input-mode${value === mode.id ? ' is-selected' : ''}`}
          disabled={disabled}
          key={mode.id}
          onClick={() => onChange(mode.id)}
          type="button"
        >
          <span className="mode-step">0{index + 1}</span>
          <span className="mode-label">{mode.label}<small>{mode.detail}</small></span>
          <span className="mode-indicator" aria-hidden="true" />
        </button>
      ))}
    </div>
  )
}
