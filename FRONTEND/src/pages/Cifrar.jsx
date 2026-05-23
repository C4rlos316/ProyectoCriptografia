import { useState } from 'react'
import axios from 'axios'

const API = 'http://127.0.0.1:8000'

export default function Cifrar() {
  const [archivo, setArchivo] = useState(null)
  const [publicas, setPublicas] = useState([''])
  const [firmaPrivada, setFirmaPrivada] = useState('')
  const [firmaPassword, setFirmaPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)

  const addDestinatario = () => setPublicas([...publicas, ''])
  const updateDestinatario = (i, val) => {
    const arr = [...publicas]; arr[i] = val; setPublicas(arr)
  }
  const removeDestinatario = (i) => setPublicas(publicas.filter((_, idx) => idx !== i))

  const handleSubmit = async () => {
    if (!archivo || publicas.some(p => !p.trim())) {
      setError('Selecciona un archivo y proporciona al menos una llave pública'); return
    }
    if (firmaPrivada.trim() && !firmaPassword.trim()) {
      setError('Proporciona la contraseña de tu llave de firma'); return
    }
    setLoading(true); setError(''); setSuccess('')
    try {
      const form = new FormData()
      form.append('archivo', archivo)
      publicas.forEach(p => form.append('publicas', p.trim()))
      if (firmaPrivada.trim()) {
        form.append('firma_privada', firmaPrivada.trim())
        form.append('firma_password', firmaPassword.trim())
      }

      const response = await axios.post(`${API}/api/cifrar`, form, { responseType: 'blob' })
      const url = URL.createObjectURL(response.data)
      const a = document.createElement('a')
      a.href = url; a.download = archivo.name + '.vault'; a.click()
      setSuccess('Archivo cifrado y descargado correctamente')
    } catch (e) {
      setError('Error al cifrar. Verifica las llaves públicas.')
    } finally { setLoading(false) }
  }

  return (
    <>
      <div className="page-header">
        <h2>Cifrar archivo</h2>
        <p>Cifrado híbrido AES-GCM + RSA-OAEP multidestinatario</p>
      </div>

      <div className="card">
        <div className="field">
          <label>Archivo a cifrar</label>
          <label className="file-label">
            <span>↑</span>
            {archivo ? archivo.name : 'Seleccionar archivo'}
            <input type="file" onChange={e => setArchivo(e.target.files[0])} />
          </label>
        </div>

        <div className="field">
          <label>Llaves públicas de destinatarios (PEM)</label>
          {publicas.map((p, i) => (
            <div key={i} style={{display:'flex', gap:'0.5rem', marginBottom:'0.5rem'}}>
              <textarea placeholder="-----BEGIN PUBLIC KEY-----..." value={p}
                onChange={e => updateDestinatario(i, e.target.value)}
                style={{flex:1, minHeight:'80px'}} />
              {publicas.length > 1 &&
                <button className="btn btn-ghost" style={{alignSelf:'flex-start'}}
                  onClick={() => removeDestinatario(i)}>✕</button>}
            </div>
          ))}
          <button className="btn btn-ghost" onClick={addDestinatario}
            style={{marginTop:'0.25rem'}}>
            + Agregar destinatario
          </button>
        </div>

        <hr className="divider" />

        <div className="field">
          <label>Llave privada de firma Ed25519 <span style={{color:'#334155'}}>(opcional)</span></label>
          <textarea placeholder="-----BEGIN ENCRYPTED PRIVATE KEY-----..." value={firmaPrivada}
            onChange={e => { setFirmaPrivada(e.target.value); if (!e.target.value) setFirmaPassword('') }} />
        </div>

        {firmaPrivada.trim() && (
          <div className="field">
            <label>Contraseña de la llave de firma</label>
            <input type="password" placeholder="Contraseña con que protegiste la llave"
              value={firmaPassword} onChange={e => setFirmaPassword(e.target.value)} />
          </div>
        )}

        <button className="btn btn-primary" onClick={handleSubmit} disabled={loading || !archivo}>
          {loading ? 'Cifrando...' : '🔒 Cifrar y descargar .vault'}
        </button>

        {error && <div className="alert alert-error" style={{marginTop:'0.75rem'}}>{error}</div>}
        {success && <div className="alert alert-success" style={{marginTop:'0.75rem'}}>{success}</div>}
      </div>
    </>
  )
}