// Type declarations for .vue SFCs and Vite env

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  var component: DefineComponent<{}, {}, any>
  export default component
}

declare global {
  interface Window {
    binmindAPI?: ElectronAPI
  }
}

interface ElectronAPI {
  selectBinary?: () => Promise<string | null>
  startBackend?: () => Promise<{ status: string; port: number }>
  platform?: string
  electronVersion?: string
  nodeVersion?: string
}

interface ImportMetaEnv {
  VITE_API_BASE?: string
  VITE_APP_TITLE?: string
  VITE_DEV_MODE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
