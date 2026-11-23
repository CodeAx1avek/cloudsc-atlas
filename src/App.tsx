import { useEffect, useState } from 'react'
import { Route, Routes, useLocation } from 'react-router-dom'
import { Nav } from '@/components/Nav'
import { Footer } from '@/components/Footer'
import { SearchDialog } from '@/components/SearchDialog'
import { HomePage } from '@/pages/HomePage'
import { CurriculumPage, CloudPage } from '@/pages/CurriculumPage'
import { TopicPage } from '@/components/TopicPage'
import { FeedPage } from '@/pages/FeedPage'
import { MethodPage } from '@/pages/MethodPage'
import { NotFoundPage } from '@/pages/NotFoundPage'

export default function App() {
  const [searchOpen, setSearchOpen] = useState(false)
  const location = useLocation()

  // Close the search overlay whenever the route changes.
  useEffect(() => {
    setSearchOpen(false)
  }, [location.pathname])

  // Cmd/Ctrl-K opens search from anywhere.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setSearchOpen((v) => !v)
      }
      if (e.key === '/' && !isTyping(e)) {
        e.preventDefault()
        setSearchOpen(true)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="app">
      <Nav onOpenSearch={() => setSearchOpen(true)} />
      <main className="app__main">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/curriculum" element={<CurriculumPage />} />
          <Route path="/cloud/:cloudId" element={<CloudPage />} />
          <Route path="/topic/*" element={<TopicPage />} />
          <Route path="/advisories" element={<FeedPage />} />
          <Route path="/method" element={<MethodPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>
      <Footer />
      {searchOpen ? <SearchDialog onClose={() => setSearchOpen(false)} /> : null}
    </div>
  )
}

function isTyping(e: KeyboardEvent): boolean {
  const el = e.target as HTMLElement | null
  if (!el) return false
  const tag = el.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || el.isContentEditable
}
