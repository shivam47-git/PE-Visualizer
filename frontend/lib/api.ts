import axios from 'axios';
import type {
  PEInfo, DisasmResult, YaraScanResult, EntropyMap,
  SessionInfo, UploadResult, HexRow
} from './types';

const api = axios.create({ baseURL: '', timeout: 300000 });

export async function uploadFile(file: File): Promise<UploadResult> {
  const form = new FormData();
  form.append('file', file, file.name);
  const res = await axios.post('/api/upload', form, {
    timeout: 300000,
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return res.data;
}

export async function analyzeSession(sessionId: string): Promise<PEInfo> {
  const res = await api.get('/api/analyze', { params: { session: sessionId } });
  return res.data;
}

export async function disassemble(
  sessionId: string,
  rva: number,
  size = 512,
  maxInsns = 1000
): Promise<DisasmResult> {
  const res = await api.get('/api/disasm', {
    params: { session: sessionId, rva, size, max: maxInsns }
  });
  return res.data;
}

export async function hexDump(
  sessionId: string,
  rva: number,
  size = 256
): Promise<HexRow[]> {
  const res = await api.get('/api/hexdump', {
    params: { session: sessionId, rva, size }
  });
  return res.data;
}

export async function scanYara(
  sessionId: string,
  rules = ''
): Promise<YaraScanResult> {
  const res = await api.post('/api/yara', { session: sessionId, rules });
  return res.data;
}

export async function getStrings(
  sessionId: string,
  params: {
    filter?: string;
    encoding?: string;
    q?: string;
    limit?: number;
    offset?: number;
  } = {}
) {
  const res = await api.get('/api/strings', {
    params: { session: sessionId, ...params }
  });
  return res.data;
}

export async function getEntropyMap(sessionId: string): Promise<EntropyMap> {
  const res = await api.get('/api/entropy_map', { params: { session: sessionId } });
  return res.data;
}

export async function getSessions(): Promise<SessionInfo[]> {
  const res = await api.get('/api/sessions');
  return res.data;
}

export async function deleteSession(sessionId: string): Promise<void> {
  await api.delete('/api/session', { params: { id: sessionId } });
}

export async function getSectionData(sessionId: string, name: string) {
  const res = await api.get('/api/section_data', {
    params: { session: sessionId, name }
  });
  return res.data;
}

export function formatHex(n: number | undefined | null, width = 8): string {
  if (n === undefined || n === null) return '0x' + '0'.repeat(width);
  return '0x' + n.toString(16).toUpperCase().padStart(width, '0');
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function severityColor(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return 'text-red-400 bg-red-950/60 border-red-700';
    case 'HIGH':     return 'text-orange-400 bg-orange-950/60 border-orange-700';
    case 'MEDIUM':   return 'text-yellow-400 bg-yellow-950/60 border-yellow-700';
    case 'LOW':      return 'text-blue-400 bg-blue-950/60 border-blue-700';
    case 'INFO':     return 'text-slate-400 bg-slate-950/60 border-slate-700';
    default:         return 'text-slate-400 bg-slate-900 border-slate-700';
  }
}

export function entropyColor(entropy: number): string {
  if (entropy > 7.2) return '#ef4444';
  if (entropy > 6.5) return '#f97316';
  if (entropy > 5.5) return '#eab308';
  if (entropy > 3.5) return '#22c55e';
  return '#64748b';
}

export function instrColor(colorClass: string): string {
  switch (colorClass) {
    case 'call':      return '#c084fc';
    case 'jmp':       return '#60a5fa';
    case 'jcc':       return '#93c5fd';
    case 'ret':       return '#f87171';
    case 'nop':       return '#4b5563';
    case 'interrupt': return '#fb923c';
    case 'syscall':   return '#a78bfa';
    case 'privileged':return '#f43f5e';
    case 'stack':     return '#34d399';
    case 'mov':       return '#94a3b8';
    case 'invalid':   return '#6b7280';
    default:          return '#e2e8f0';
  }
}
