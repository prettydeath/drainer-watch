import { Component, type ReactNode } from 'react'

/** Keeps one broken section (or a failed lazy chunk) from blanking the whole page. */
export class Boundary extends Component<{ children: ReactNode; what: string }, { error: string | null }> {
  state = { error: null as string | null }
  static getDerivedStateFromError(e: unknown) { return { error: e instanceof Error ? e.message : String(e) } }
  render() {
    if (this.state.error) return <p className="empty">The {this.props.what} could not be drawn ({this.state.error}). Reload the page to try again.</p>
    return this.props.children
  }
}
