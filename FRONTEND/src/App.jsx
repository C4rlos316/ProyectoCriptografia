import { Routes, Route, NavLink } from 'react-router-dom'
import Identidad from './pages/Identidad'
import IdentidadFirma from './pages/IdentidadFirma'
import Cifrar from './pages/Cifrar'
import Descifrar from './pages/Descifrar'
import Home from './pages/Home'
import './App.css'

export default function App() {
  return (
    <div className="app">
      <nav className="navbar">
        <div className="brand">
          <div className="brand-icon">🔐</div>
          <span>Secure Vault</span>
        </div>
        <div className="nav-links">
          <NavLink to="/identidad">Identidad</NavLink>
          <NavLink to="/identidad-firma">Firma</NavLink>
          <NavLink to="/cifrar">Cifrar</NavLink>
          <NavLink to="/descifrar">Descifrar</NavLink>
        </div>
      </nav>
      <main className="container">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/identidad" element={<Identidad />} />
          <Route path="/identidad-firma" element={<IdentidadFirma />} />
          <Route path="/cifrar" element={<Cifrar />} />
          <Route path="/descifrar" element={<Descifrar />} />
        </Routes>
      </main>
    </div>
  )
}