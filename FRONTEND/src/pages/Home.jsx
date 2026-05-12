import { useNavigate } from 'react-router-dom'

const equipo = [
  { nombre: 'Hernández Ramírez Miguel Angel',   rol: 'Desarrollo · Revisor de código',         github: 'Miguel07FI' },
  { nombre: 'Hernández Gutiérrez Carlos Mario', rol: 'Desarrollo · Testing · Project Manager', github: 'C4rlos316' },
  { nombre: 'Solís Espinosa Andrea Vianney',    rol: 'Desarrollo · Arquitectura · Diseño',     github: 'aviansol' },
  { nombre: 'Rivera Lopez David Zaid',          rol: 'Desarrollo · Documentación · Riesgos',   github: 'AvalonRD' },
  { nombre: 'Suárez Román Clara Alin',          rol: 'Desarrollo · Documentación · Seguridad', github: 'clarasrzfi' },
]

const features = [
  { icon: '🔑', title: 'Identidad RSA',     desc: 'Genera llaves RSA-2048 protegidas con contraseña',  path: '/identidad' },
  { icon: '✍️', title: 'Firma Ed25519',     desc: 'Llaves de firma digital para autenticación de origen', path: '/identidad-firma' },
  { icon: '🔒', title: 'Cifrar archivo',    desc: 'Cifrado híbrido AES-GCM + RSA-OAEP multidestinatario', path: '/cifrar' },
  { icon: '🔓', title: 'Descifrar archivo', desc: 'Recupera archivos .vault con tu llave privada',     path: '/descifrar' },
]

export default function Home() {
  const navigate = useNavigate()

  return (
    <>
      {/* Hero */}
      <div style={{textAlign:'center', padding:'2rem 0 1.5rem'}}>
        <div style={{
          display:'inline-flex', alignItems:'center', justifyContent:'center',
          width:'56px', height:'56px', borderRadius:'14px',
          background:'#534AB7', fontSize:'24px', marginBottom:'1rem'
        }}>🔐</div>
        <h1 style={{fontSize:'1.6rem', fontWeight:'500', color:'#e2e8f0', marginBottom:'0.4rem'}}>
          Secure Digital Document Vault
        </h1>
        <p style={{fontSize:'0.9rem', color:'#64748b', maxWidth:'420px', margin:'0 auto 0.75rem'}}>
          Bóveda segura de documentos con cifrado híbrido, firmas digitales y gestión de llaves protegidas
        </p>
        <div style={{display:'flex', gap:'8px', justifyContent:'center', flexWrap:'wrap'}}>
          {['AES-GCM-256', 'RSA-OAEP', 'Ed25519', 'PBKDF2'].map(tag => (
            <span key={tag} style={{
              padding:'0.2rem 0.65rem', borderRadius:'99px',
              background:'#1a1d2e', border:'0.5px solid #2d3148',
              fontSize:'0.75rem', color:'#94a3b8'
            }}>{tag}</span>
          ))}
        </div>
      </div>

      {/* Info académica */}
      <div style={{
        background:'#0f0f18', border:'0.5px solid #1e2035',
        borderRadius:'12px', padding:'1rem 1.25rem',
        marginBottom:'1.5rem', display:'flex', gap:'2rem', flexWrap:'wrap',
        justifyContent:'center'
      }}>
        {[
          { label: 'Materia',      value: 'Criptografía' },
          { label: 'Semestre',     value: '2026-2' },
          { label: 'Institución',  value: 'Facultad de Ingeniería, UNAM' },
        ].map(item => (
          <div key={item.label} style={{textAlign:'center'}}>
            <p style={{fontSize:'0.7rem', color:'#475569', textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:'2px'}}>
              {item.label}
            </p>
            <p style={{fontSize:'0.875rem', color:'#e2e8f0', fontWeight:'500'}}>{item.value}</p>
          </div>
        ))}
      </div>

      {/* Features */}
      <div style={{
        display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(240px, 1fr))',
        gap:'0.75rem', marginBottom:'1.5rem'
      }}>
        {features.map(f => (
          <button key={f.path} onClick={() => navigate(f.path)} style={{
            background:'#0f0f18', border:'0.5px solid #1e2035',
            borderRadius:'12px', padding:'1.1rem',
            textAlign:'left', cursor:'pointer',
            transition:'border-color 0.15s, background 0.15s',
          }}
          onMouseEnter={e => { e.currentTarget.style.borderColor='#534AB7'; e.currentTarget.style.background='#12122a' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor='#1e2035'; e.currentTarget.style.background='#0f0f18' }}
          >
            <div style={{fontSize:'20px', marginBottom:'0.5rem'}}>{f.icon}</div>
            <p style={{fontSize:'0.9rem', fontWeight:'500', color:'#e2e8f0', marginBottom:'0.25rem'}}>{f.title}</p>
            <p style={{fontSize:'0.78rem', color:'#64748b'}}>{f.desc}</p>
          </button>
        ))}
      </div>

      {/* Equipo */}
      <div style={{
        background:'#0f0f18', border:'0.5px solid #1e2035',
        borderRadius:'12px', padding:'1.25rem', marginBottom:'1rem'
      }}>
        <p style={{
          fontSize:'0.7rem', color:'#475569', textTransform:'uppercase',
          letterSpacing:'0.08em', marginBottom:'1rem'
        }}>Equipo de desarrollo</p>
        <div style={{display:'flex', flexDirection:'column', gap:'0.6rem'}}>
          {equipo.map(m => (
            <div key={m.github} style={{
              display:'flex', alignItems:'center', justifyContent:'space-between',
              gap:'1rem', flexWrap:'wrap'
            }}>
              <div style={{display:'flex', alignItems:'center', gap:'10px'}}>
                <div style={{
                  width:'32px', height:'32px', borderRadius:'50%',
                  background:'#1a1d2e', border:'0.5px solid #2d3148',
                  display:'flex', alignItems:'center', justifyContent:'center',
                  fontSize:'0.75rem', fontWeight:'500', color:'#a5b4fc', flexShrink:0
                }}>
                  {m.nombre.split(' ').map(n => n[0]).slice(0,2).join('')}
                </div>
                <div>
                  <p style={{fontSize:'0.85rem', color:'#e2e8f0', fontWeight:'500'}}>{m.nombre}</p>
                  <p style={{fontSize:'0.75rem', color:'#64748b'}}>{m.rol}</p>
                </div>
              </div>
              <a href={`https://github.com/${m.github}`} target="_blank" rel="noreferrer"
                style={{fontSize:'0.75rem', color:'#534AB7', textDecoration:'none'}}>
                @{m.github}
              </a>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}