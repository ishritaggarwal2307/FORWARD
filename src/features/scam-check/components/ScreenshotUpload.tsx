import { useRef, useState } from 'react'

interface ScreenshotUploadProps {
  file: File | null
  disabled: boolean
  onSelect: (file: File | null) => void
}

const allowedTypes = ['image/jpeg', 'image/png', 'image/webp']
const maxFileSize = 10 * 1024 * 1024

export function ScreenshotUpload({ file, disabled, onSelect }: ScreenshotUploadProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [error, setError] = useState('')

  function chooseFile(selected: File | undefined) {
    if (!selected) return
    setError('')

    if (!allowedTypes.includes(selected.type)) {
      setError('Choose a JPG, PNG, or WebP image.')
      return
    }
    if (selected.size > maxFileSize) {
      setError('This image is larger than 10 MB. Choose a smaller screenshot.')
      return
    }
    onSelect(selected)
  }

  function removeFile() {
    setError('')
    onSelect(null)
  }

  return (
    <div className="screenshot-input">
      <input
        accept={allowedTypes.join(',')}
        className="visually-hidden"
        disabled={disabled}
        id="screenshot-file"
        onChange={(event) => {
          chooseFile(event.currentTarget.files?.[0])
          event.currentTarget.value = ''
        }}
        ref={inputRef}
        type="file"
      />
      {file ? (
        <div className="selected-image">
          <span className="upload-mark" aria-hidden="true">▧</span>
          <div className="selected-image-info">
            <span>{file.name}</span>
            <small>{(file.size / 1024 / 1024).toFixed(1)} MB · Held only for this check</small>
            <button className="remove-image" disabled={disabled} onClick={removeFile} type="button">Remove image</button>
          </div>
        </div>
      ) : (
        <label className="upload-dropzone" htmlFor="screenshot-file">
          <span className="upload-mark" aria-hidden="true">＋</span>
          <span><strong>Choose a screenshot</strong><small>JPG, PNG, or WebP · up to 10 MB</small></span>
          <span className="button button-small upload-button">Browse files</span>
        </label>
      )}
      <p className="privacy-note"><span aria-hidden="true">◇</span> Your image is processed in this browser and is never uploaded. English OCR resources may download the first time you analyze an image.</p>
      {error && <p className="field-error" role="alert">{error}</p>}
    </div>
  )
}
