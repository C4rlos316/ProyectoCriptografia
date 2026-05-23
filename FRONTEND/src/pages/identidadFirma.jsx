import { useState } from 'react'
import axios from 'axios'

const API = 'http://127.0.0.1:8000'

function getPasswordStrength(pwd) {
  let score = 0
  if (pwd.length >= 8) score++
  if (pwd.length >= 12) score++
  if (/[A-Z]/.test(pwd)) score++
  if (/[0-9]/.test(pwd)) score++
  if (/[^a-zA-Z0-9]/.test(pwd)) score++
  return score
}

const strengthLabel = ['', 'Muy débil', 'Débil', 'Regular', 'Fuerte', 'Muy fuerte']
const strengthColor = ['', '#ef4444', '#f97316', '#eab308', '#22c55e', '#10b981']

export default function IdentidadFirma() {
  const [usuario, setUsuario] = useState('')
  const [password, setPassword] = useState('')
  const [resultado, setResultado] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const strength = getPasswordStrength(password)
  const isPasswordValid = strength >= 3

  const download = (content, filename) => {
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click()
  }

  const handleSubmit = async () => {
    if (!usuario.trim() || !isPasswordValid) return
    setLoading(true); setError(''); setResultado(null)
    try {
      const { data } = await axios.post(`${API}/api/identidad-firma`, { usuario, password })
      setResultado(data)
      download(data.signing_private_key, `${usuario}_signing_private.pem`)
    } catch (e) {
      setError(e.response?.data?.detail || 'Error al generar llaves de firma')
    } finally { setLoading(false) }
  }

  return (
    <>
      <div className="page-header">
        <h2>Generar llaves de firma Ed25519</h2>
        <p>Par de llaves para autenticación de origen y firma digital</p>
      </div>

      <div className="card">
        <div className="field">
          <label>Nombre de usuario</label>
          <input type="text" placeholder="ej. alice" value={usuario}
            onChange={e => setUsuario(e.target.value)} />
        </div>

        <div className="field">
          <label>Contraseña para proteger la llave privada de firma</label>
          <input type="password" placeholder="Letras, números y símbolos"
            value={password} onChange={e => setPassword(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()} />

          {password.length > 0 && (
            <div style={{marginTop:'6px'}}>
              <div style={{display:'flex', gap:'3px', marginBottom:'4px'}}>
                {[1,2,3,4,5].map(i => (
                  <div key={i} style={{
                    flex:1, height:'3px', borderRadius:'2px',
                    background: i <= strength ? strengthColor[strength] : '#1e2035',
                    transition: 'background 0.2s'
                  }} />
                ))}
              </div>
              <span style={{fontSize:'0.75rem', color: strengthColor[strength]}}>
                {strengthLabel[strength]}
              </span>
              {!isPasswordValid && (
                <ul style={{marginTop:'0.35rem', paddingLeft:'1.1rem', fontSize:'0.75rem', color:'#475569'}}>
                  {password.length < 8 && <li>Mínimo 8 caracteres</li>}
                  {!/[A-Z]/.test(password) && <li>Al menos una mayúscula</li>}
                  {!/[0-9]/.test(password) && <li>Al menos un número</li>}
                  {!/[^a-zA-Z0-9]/.test(password) && <li>Al menos un símbolo (!@#$...)</li>}
                </ul>
              )}
            </div>
          )}
        </div>

        <button className="btn btn-primary" onClick={handleSubmit}
          disabled={loading || !usuario.trim() || !isPasswordValid}>
          {loading ? 'Generando...' : 'Generar llaves de firma'}
        </button>

        {error && <div className="alert alert-error" style={{marginTop:'0.75rem'}}>{error}</div>}
      </div>

      {resultado && (
        <>
          <div className="result-box">
            <div className="result-box-header">
              <h3>Llave pública de firma</h3>
              <button className="btn btn-ghost" onClick={() => download(resultado.signing_public_key, `${usuario}_signing_public.pem`)}>
                ↓ Descargar .pem
              </button>
            </div>
            <pre>{resultado.signing_public_key}</pre>
          </div>

          <div className="alert alert-warning">
            <span>⚠</span>
            <p>Tu llave privada de firma fue descargada automáticamente y está protegida con tu contraseña. Guárdala en un lugar seguro — no se puede recuperar.
              <button className="btn btn-ghost" style={{marginTop:'0.5rem', display:'block'}}
                onClick={() => download(resultado.signing_private_key, `${usuario}_signing_private.pem`)}>
                ↓ Volver a descargar signing_private.pem
              </button>
            </p>
          </div>
        </>
      )}
    </>
  )
}