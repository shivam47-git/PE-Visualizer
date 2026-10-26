import { create } from 'zustand';
import type { PEInfo, PanelId, SessionInfo } from './types';

interface AppStore {
  // Session
  sessionId: string | null;
  sessions: SessionInfo[];
  peInfo: PEInfo | null;
  loading: boolean;
  error: string | null;

  // Navigation
  activePanel: PanelId;
  
  // Disasm state
  disasmRva: number;
  disasmSize: number;
  disasmFollowEP: boolean;
  
  // Hex view state
  hexRva: number;
  hexSize: number;
  hexHighlight: { start: number; end: number } | null;

  // Strings state
  stringFilter: string;
  stringEncoding: string;
  stringQuery: string;
  
  // YARA state
  yaraRules: string;
  
  // UI
  sidebarOpen: boolean;
  theme: 'dark' | 'light';
  
  // Actions
  setSession: (id: string | null) => void;
  setSessions: (sessions: SessionInfo[]) => void;
  setPeInfo: (info: PEInfo | null) => void;
  setLoading: (v: boolean) => void;
  setError: (e: string | null) => void;
  setActivePanel: (p: PanelId) => void;
  setDisasmRva: (rva: number) => void;
  setHexRva: (rva: number) => void;
  setHexHighlight: (h: { start: number; end: number } | null) => void;
  setStringFilter: (f: string) => void;
  setStringEncoding: (e: string) => void;
  setStringQuery: (q: string) => void;
  setYaraRules: (r: string) => void;
  toggleSidebar: () => void;
  toggleTheme: () => void;
  reset: () => void;
}

export const useStore = create<AppStore>((set) => ({
  sessionId: null,
  sessions: [],
  peInfo: null,
  loading: false,
  error: null,
  activePanel: 'overview',
  disasmRva: 0,
  disasmSize: 512,
  disasmFollowEP: true,
  hexRva: 0,
  hexSize: 256,
  hexHighlight: null,
  stringFilter: '',
  stringEncoding: '',
  stringQuery: '',
  yaraRules: '',
  sidebarOpen: true,
  theme: 'dark',

  setSession: (id) => set({ sessionId: id }),
  setSessions: (sessions) => set({ sessions }),
  setPeInfo: (info) => set({ peInfo: info }),
  setLoading: (v) => set({ loading: v }),
  setError: (e) => set({ error: e }),
  setActivePanel: (p) => set({ activePanel: p }),
  setDisasmRva: (rva) => set({ disasmRva: rva }),
  setHexRva: (rva) => set({ hexRva: rva }),
  setHexHighlight: (h) => set({ hexHighlight: h }),
  setStringFilter: (f) => set({ stringFilter: f }),
  setStringEncoding: (e) => set({ stringEncoding: e }),
  setStringQuery: (q) => set({ stringQuery: q }),
  setYaraRules: (r) => set({ yaraRules: r }),
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
  toggleTheme: () => set((s) => ({ theme: s.theme === 'dark' ? 'light' : 'dark' })),
  reset: () => set({
    sessionId: null, peInfo: null, loading: false, error: null,
    activePanel: 'overview', disasmRva: 0, hexRva: 0, hexHighlight: null
  }),
}));
