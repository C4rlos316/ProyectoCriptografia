import { useState } from 'react'
import axios from 'axios'

const API = 'http://127.0.0.1:8000'

export default function Descifrar() {
  const [archivo, setArchivo] = useState(null)
  const [keystore, setKeystore] = useState('')
  const [password, setPassword] = useState('')
  const [firmaPublica, setFirmaPublica] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async () => {
    if (!archivo || !keystore.trim() || !password.trim()) {
      setError('Selecciona un archivo .vault, proporciona tu keystore y contraseña'); return
    }
    setLoading(true); setError(''); setSuccess('')
    try {
      const form = new FormData()
      form.append('archivo', archivo)
      form.append('keystore', keystore.trim())
      form.append('password', password.trim())
      if (firmaPublica.trim()) form.append('firma_publica', firmaPublica.trim())

      const response = await axios.post(`${API}/api/descifrar`, form, { responseType: 'blob' })
      const url = URL.createObjectURL(response.data)
      const a = document.createElement('a')
      a.href = url
      a.download = archivo.name.replace('.vault', '')
      a.click()
      setSuccess('Archivo descifrado y descargado correctamente')
    } catch (e) {
      setError('Descifrado fallido. Verifica el archivo, el keystore, la contraseña y la firma.')
    } finally { setLoading(false) }
  }

  return (
    <>
      <div className="page-header">
        <h2>Descifrar archivo</h2>
        <p>Recupera un archivo .vault con tu keystore privado</p>
      </div>

      <div className="card">
        <div className="field">
          <label>Archivo .vault</label>
          <label className="file-label">
            <span>↑</span>
            {archivo ? archivo.name : 'Seleccionar .vault'}
            <input type="file" accept=".vault" onChange={e => setArchivo(e.target.files[0])} />
          </label>
        </div>

        <div className="field">
          <label>Tu keystore privado (contenido del .keystore)</label>
          <textarea placeholder='{"encrypted_key": "...", "salt": "...", "kdf": "argon2id", ...}'
            value={keystore} onChange={e => setKeystore(e.target.value)} />
        </div>

        <div className="field">
          <label>Contraseña de tu keystore</label>
          <input type="password" placeholder="Contraseña con que protegiste la llave"
            value={password} onChange={e => setPassword(e.target.value)} />
        </div>

        <hr className="divider" />

        <div className="field">
          <label>Llave pública de firma Ed25519 <span style={{color:'#334155'}}>(opcional)</span></label>
          <textarea placeholder="-----BEGIN PUBLIC KEY-----..." value={firmaPublica}
            onChange={e => setFirmaPublica(e.target.value)} />
        </div>

        <button className="btn btn-primary" onClick={handleSubmit}
          disabled={loading || !archivo || !keystore.trim() || !password.trim()}>
          {loading ? 'Descifrando...' : '🔓 Descifrar y descargar'}
        </button>

        {error && <div className="alert alert-error" style={{marginTop:'0.75rem'}}>{error}</div>}
        {success && <div className="alert alert-success" style={{marginTop:'0.75rem'}}>{success}</div>}
      </div>
    </>
  )
}