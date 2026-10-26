'use client';
import React, { useState, useCallback, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload, FileCode2, Shield, AlertTriangle, Terminal,
  Grid3X3, Database, Binary, Search, Zap, ChevronRight,
  Menu, X, Moon, Sun, Trash2, RefreshCw, Copy, Check,
  ChevronDown, Info, AlertCircle, AlertOctagon, Bug,
  Cpu, HardDrive, Lock, Network, Code2, Layers,
  BarChart2, Hash, FileSearch, Activity
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, ReferenceLine, Cell, RadarChart,
  Radar, PolarGrid, PolarAngleAxis
} from 'recharts';
import { useStore } from '../lib/store';
import {
  uploadFile, analyzeSession, formatHex, formatSize,
  severityColor, entropyColor, instrColor, disassemble,
  scanYara, getStrings, getEntropyMap, hexDump
} from '../lib/api';
import type {
  PanelId, SectionInfo, ImportDLL, DisasmInstruction,
  Anomaly, YaraMatch, EntropyBlock
} from '../lib/types';

// ─── Utility ─────────────────────────────────────────────────────────────────
function cn(...classes: (string | boolean | undefined)[]) {
  return classes.filter(Boolean).join(' ');
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="p-1 rounded hover:bg-white/10 transition-colors text-slate-500 hover:text-slate-300"
    >
      {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
    </button>
  );
}

function HexVal({ n, width = 8 }: { n: number | undefined | null; width?: number }) {
  const s = formatHex(n, width);
  return (
    <span className="font-mono text-cyan-400 text-xs select-all" title={n?.toString() ?? '0'}>
      {s}
    </span>
  );
}

function Badge({ children, variant = 'default' }: {
  children: React.ReactNode;
  variant?: 'default' | 'red' | 'orange' | 'yellow' | 'green' | 'blue' | 'purple';
}) {
  const cls = {
    default: 'bg-slate-800 text-slate-300 border-slate-700',
    red:    'bg-red-950/60 text-red-400 border-red-700/50',
    orange: 'bg-orange-950/60 text-orange-400 border-orange-700/50',
    yellow: 'bg-yellow-950/60 text-yellow-400 border-yellow-700/50',
    green:  'bg-green-950/60 text-green-400 border-green-700/50',
    blue:   'bg-blue-950/60 text-blue-400 border-blue-700/50',
    purple: 'bg-purple-950/60 text-purple-400 border-purple-700/50',
  }[variant];
  return (
    <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono border', cls)}>
      {children}
    </span>
  );
}

function SeverityBadge({ sev }: { sev: string }) {
  const v = { CRITICAL: 'red', HIGH: 'orange', MEDIUM: 'yellow', LOW: 'blue', INFO: 'default' } as const;
  return <Badge variant={v[sev as keyof typeof v] || 'default'}>{sev}</Badge>;
}

// ─── KV Row ──────────────────────────────────────────────────────────────────
function KVRow({ label, value, hex, copy }: {
  label: string; value: React.ReactNode; hex?: boolean; copy?: string;
}) {
  return (
    <div className="flex items-baseline gap-2 py-1 border-b border-white/5 group">
      <span className="text-slate-500 text-xs font-mono w-44 shrink-0 truncate">{label}</span>
      <span className={cn('text-xs font-mono flex-1 break-all', hex ? 'text-cyan-400' : 'text-slate-200')}>
        {value}
      </span>
      {copy && <CopyButton text={copy} />}
    </div>
  );
}

// ─── Section Entropy Bar ──────────────────────────────────────────────────────
function EntropyBar({ value }: { value: number }) {
  const pct = (value / 8) * 100;
  const color = entropyColor(value);
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-mono w-8 text-right" style={{ color }}>{value.toFixed(2)}</span>
    </div>
  );
}

// ─── Nav Item ─────────────────────────────────────────────────────────────────
function NavItem({ id, icon: Icon, label, badge, active, onClick }: {
  id: PanelId; icon: React.ElementType; label: string;
  badge?: number | string; active: boolean; onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full flex items-center gap-2.5 px-3 py-1.5 rounded-md text-left transition-all',
        active
          ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
          : 'text-slate-500 hover:text-slate-300 hover:bg-white/5 border border-transparent'
      )}
    >
      <Icon size={14} className={active ? 'text-cyan-400' : ''} />
      <span className="text-xs flex-1 truncate">{label}</span>
      {badge !== undefined && badge !== 0 && (
        <span className={cn(
          'text-[10px] font-mono px-1 rounded',
          active ? 'bg-cyan-500/30 text-cyan-300' : 'bg-slate-800 text-slate-500'
        )}>{badge}</span>
      )}
    </button>
  );
}

// ─── Panels ───────────────────────────────────────────────────────────────────

// Overview Panel
function OverviewPanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;

  const { hashes, file_header, optional_header, anomalies, sections } = peInfo;

  const sevCounts = anomalies.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const radarData = [
    { subject: 'Sections', value: Math.min(sections.length * 10, 100) },
    { subject: 'Imports', value: Math.min(peInfo.import_count / 5, 100) },
    { subject: 'Exports', value: Math.min(peInfo.export_count * 5, 100) },
    { subject: 'Entropy', value: (peInfo.file_entropy / 8) * 100 },
    { subject: 'Anomalies', value: Math.min(anomalies.length * 8, 100) },
    { subject: 'Strings', value: Math.min(peInfo.string_count / 100, 100) },
  ];

  const sectionData = sections.map(s => ({
    name: s.name || '(unnamed)',
    entropy: parseFloat(s.entropy.toFixed(3)),
    size: s.raw_size,
  }));

  return (
    <div className="space-y-4">
      {/* File identity */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-slate-900/60 rounded-lg border border-white/10 p-4 col-span-2">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h3 className="text-slate-200 font-semibold text-sm truncate max-w-lg">
                {peInfo.file_path}
              </h3>
              <div className="flex items-center gap-2 mt-1">
                <Badge variant={peInfo.pe_type === 'DLL' ? 'purple' : peInfo.pe_type === 'SYS' ? 'red' : 'blue'}>
                  {peInfo.pe_type}
                </Badge>
                <Badge variant={optional_header.is_64bit ? 'green' : 'yellow'}>
                  {optional_header.is_64bit ? 'PE64' : 'PE32'}
                </Badge>
                <Badge>{file_header.machine_str}</Badge>
                <Badge>{optional_header.subsystem_str}</Badge>
                {peInfo.clr.present && <Badge variant="purple">.NET CLR</Badge>}
                {peInfo.tls.present && <Badge variant="orange">TLS Callbacks</Badge>}
                {peInfo.signature.signed_file && <Badge variant="green">Signed</Badge>}
              </div>
            </div>
            <span className="text-slate-500 text-xs font-mono">{formatSize(peInfo.file_size)}</span>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">MD5</p>
              <div className="flex items-center gap-1">
                <span className="text-xs font-mono text-slate-300 truncate">{hashes.md5}</span>
                <CopyButton text={hashes.md5} />
              </div>
            </div>
            <div>
              <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">SHA-256</p>
              <div className="flex items-center gap-1">
                <span className="text-xs font-mono text-slate-300 truncate">{hashes.sha256}</span>
                <CopyButton text={hashes.sha256} />
              </div>
            </div>
            <div>
              <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">ImpHash</p>
              <div className="flex items-center gap-1">
                <span className="text-xs font-mono text-slate-300 truncate">{hashes.imphash || 'N/A'}</span>
                {hashes.imphash && <CopyButton text={hashes.imphash} />}
              </div>
            </div>
          </div>
        </div>

        {/* Stats grid */}
        {[
          { label: 'Entry Point', value: formatHex(optional_header.address_of_entry_point), sub: 'RVA' },
          { label: 'Image Base', value: formatHex(optional_header.image_base, 16), sub: 'VA' },
          { label: 'Image Size', value: formatSize(optional_header.size_of_image), sub: 'loaded' },
          { label: 'Timestamp', value: file_header.timestamp_str.split(' ')[0], sub: file_header.timestamp_str.split(' ').slice(1).join(' ') },
          { label: 'Sections', value: sections.length, sub: 'total' },
          { label: 'Imports', value: peInfo.import_count, sub: `from ${peInfo.imports.length} DLLs` },
          { label: 'File Entropy', value: peInfo.file_entropy.toFixed(4), sub: peInfo.file_entropy > 7 ? '⚠ High' : 'Normal' },
          { label: 'Strings', value: peInfo.string_count.toLocaleString(), sub: 'extracted' },
        ].map((stat, i) => (
          <div key={i} className="bg-slate-900/40 rounded-lg border border-white/8 p-3">
            <p className="text-[10px] text-slate-600 uppercase tracking-wider">{stat.label}</p>
            <p className="text-slate-200 font-mono text-sm mt-1">{stat.value}</p>
            <p className="text-[10px] text-slate-600 mt-0.5">{stat.sub}</p>
          </div>
        ))}
      </div>

      {/* Anomalies summary */}
      {anomalies.length > 0 && (
        <div className="bg-slate-900/60 rounded-lg border border-orange-500/20 p-4">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle size={14} className="text-orange-400" />
            <h4 className="text-sm font-semibold text-slate-300">
              {anomalies.length} Anomalies Detected
            </h4>
            <div className="flex gap-1.5 ml-auto">
              {(['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as const).map(s =>
                sevCounts[s] ? (
                  <Badge key={s} variant={
                    s==='CRITICAL'?'red':s==='HIGH'?'orange':s==='MEDIUM'?'yellow':s==='LOW'?'blue':'default'
                  }>
                    {s[0]}{sevCounts[s]}
                  </Badge>
                ) : null
              )}
            </div>
          </div>
          <div className="space-y-1.5 max-h-48 overflow-y-auto pe-scrollbar">
            {anomalies.slice(0, 10).map((a, i) => (
              <div key={i} className={cn(
                'flex items-start gap-2 px-2 py-1.5 rounded border text-xs',
                severityColor(a.severity)
              )}>
                <SeverityBadge sev={a.severity} />
                <span className="text-slate-400 shrink-0">[{a.category}]</span>
                <span className="text-slate-300">{a.description}</span>
                {a.detail && <span className="text-slate-500 truncate">{a.detail}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Charts row */}
      <div className="grid grid-cols-2 gap-3">
        {/* Section entropy chart */}
        <div className="bg-slate-900/60 rounded-lg border border-white/10 p-4">
          <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-3">Section Entropy</h4>
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={sectionData} margin={{ top: 0, right: 0, left: -30, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 10 }} />
              <YAxis domain={[0, 8]} tick={{ fill: '#64748b', fontSize: 10 }} />
              <Tooltip
                contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 6 }}
                labelStyle={{ color: '#94a3b8' }}
                formatter={(v: number) => [v.toFixed(3), 'Entropy']}
              />
              <ReferenceLine y={7} stroke="#ef4444" strokeDasharray="3 3" />
              <ReferenceLine y={6} stroke="#f97316" strokeDasharray="3 3" />
              <Bar dataKey="entropy" radius={[2, 2, 0, 0]}>
                {sectionData.map((s, i) => (
                  <Cell key={i} fill={entropyColor(s.entropy)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Radar */}
        <div className="bg-slate-900/60 rounded-lg border border-white/10 p-4">
          <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-3">Profile Radar</h4>
          <ResponsiveContainer width="100%" height={140}>
            <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
              <PolarGrid stroke="#1e293b" />
              <PolarAngleAxis dataKey="subject" tick={{ fill: '#64748b', fontSize: 9 }} />
              <Radar dataKey="value" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.15} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Security features */}
      <div className="bg-slate-900/60 rounded-lg border border-white/10 p-4">
        <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-3">Security Features</h4>
        <div className="grid grid-cols-4 gap-2">
          {[
            { label: 'ASLR', ok: optional_header.dll_characteristics_flags.some(f => f.includes('DYNAMIC_BASE')) },
            { label: 'DEP/NX', ok: optional_header.dll_characteristics_flags.some(f => f.includes('NX_COMPAT')) },
            { label: 'CFG', ok: peInfo.load_config.has_cfg },
            { label: '/GS Cookie', ok: peInfo.load_config.has_security_cookie },
            { label: 'SEH', ok: peInfo.load_config.has_seh },
            { label: 'No SEH', ok: optional_header.dll_characteristics_flags.includes('NO_SEH') },
            { label: 'Force Integrity', ok: optional_header.dll_characteristics_flags.some(f => f.includes('FORCE_INTEGRITY')) },
            { label: 'Signed', ok: peInfo.signature.signed_file },
          ].map((f, i) => (
            <div key={i} className={cn(
              'flex items-center gap-1.5 px-2 py-1.5 rounded border text-xs',
              f.ok
                ? 'bg-green-950/40 border-green-700/40 text-green-400'
                : 'bg-slate-900 border-slate-800 text-slate-600'
            )}>
              <div className={cn('w-1.5 h-1.5 rounded-full', f.ok ? 'bg-green-400' : 'bg-slate-700')} />
              {f.label}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// Headers Panel
function HeadersPanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;
  const { dos_header, rich_header, file_header, optional_header } = peInfo;
  const [tab, setTab] = useState<'dos' | 'rich' | 'file' | 'optional' | 'datadirs'>('file');

  return (
    <div className="space-y-3">
      <div className="flex gap-1 border-b border-white/10 pb-2">
        {(['dos','file','optional','datadirs','rich'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={cn('px-3 py-1 rounded text-xs font-mono transition-colors',
              tab===t ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
            )}>
            {t.toUpperCase()}
          </button>
        ))}
      </div>

      {tab === 'dos' && (
        <div className="space-y-0.5">
          <KVRow label="e_magic" value={<HexVal n={dos_header.e_magic} width={4}/>} copy={formatHex(dos_header.e_magic,4)}/>
          <KVRow label="e_cblp" value={<HexVal n={dos_header.e_cblp} width={4}/>}/>
          <KVRow label="e_cp" value={<HexVal n={dos_header.e_cp} width={4}/>}/>
          <KVRow label="e_crlc" value={<HexVal n={dos_header.e_crlc} width={4}/>}/>
          <KVRow label="e_cparhdr" value={<HexVal n={dos_header.e_cparhdr} width={4}/>}/>
          <KVRow label="e_minalloc" value={<HexVal n={dos_header.e_minalloc} width={4}/>}/>
          <KVRow label="e_maxalloc" value={<HexVal n={dos_header.e_maxalloc} width={4}/>}/>
          <KVRow label="e_ss" value={<HexVal n={dos_header.e_ss} width={4}/>}/>
          <KVRow label="e_sp" value={<HexVal n={dos_header.e_sp} width={4}/>}/>
          <KVRow label="e_ip" value={<HexVal n={dos_header.e_ip} width={4}/>}/>
          <KVRow label="e_cs" value={<HexVal n={dos_header.e_cs} width={4}/>}/>
          <KVRow label="e_lfanew (PE offset)" value={<HexVal n={dos_header.e_lfanew}/>}/>
        </div>
      )}

      {tab === 'file' && (
        <div className="space-y-0.5">
          <KVRow label="Machine" value={`${file_header.machine_str} (${formatHex(file_header.machine,4)})`}/>
          <KVRow label="NumberOfSections" value={file_header.number_of_sections}/>
          <KVRow label="TimeDateStamp" value={<>
            <HexVal n={file_header.time_date_stamp}/> <span className="text-slate-400 ml-2">{file_header.timestamp_str}</span>
          </>}/>
          <KVRow label="PtrToSymbolTable" value={<HexVal n={file_header.pointer_to_symbol_table}/>}/>
          <KVRow label="NumberOfSymbols" value={file_header.number_of_symbols}/>
          <KVRow label="SizeOfOptionalHeader" value={<HexVal n={file_header.size_of_optional_header} width={4}/>}/>
          <KVRow label="Characteristics" value={<HexVal n={file_header.characteristics} width={4}/>}/>
          <div className="mt-2 flex flex-wrap gap-1">
            {file_header.characteristics_flags.map(f => <Badge key={f}>{f}</Badge>)}
          </div>
        </div>
      )}

      {tab === 'optional' && (
        <div className="space-y-0.5">
          <KVRow label="Magic" value={<><HexVal n={optional_header.magic} width={4}/> <span className="text-slate-400 ml-1">{optional_header.is_64bit ? 'PE64' : 'PE32'}</span></>}/>
          <KVRow label="LinkerVersion" value={optional_header.linker_version}/>
          <KVRow label="SizeOfCode" value={<><HexVal n={optional_header.size_of_code}/> <span className="text-slate-400">({formatSize(optional_header.size_of_code)})</span></>}/>
          <KVRow label="AddressOfEntryPoint" value={<HexVal n={optional_header.address_of_entry_point}/>}/>
          <KVRow label="BaseOfCode" value={<HexVal n={optional_header.base_of_code}/>}/>
          <KVRow label="ImageBase" value={<HexVal n={optional_header.image_base} width={16}/>}/>
          <KVRow label="SectionAlignment" value={<HexVal n={optional_header.section_alignment}/>}/>
          <KVRow label="FileAlignment" value={<HexVal n={optional_header.file_alignment}/>}/>
          <KVRow label="OperatingSystemVersion" value={optional_header.os_version}/>
          <KVRow label="ImageVersion" value={optional_header.image_version}/>
          <KVRow label="SubsystemVersion" value={optional_header.subsystem_version}/>
          <KVRow label="SizeOfImage" value={<><HexVal n={optional_header.size_of_image}/> <span className="text-slate-400">({formatSize(optional_header.size_of_image)})</span></>}/>
          <KVRow label="SizeOfHeaders" value={<HexVal n={optional_header.size_of_headers}/>}/>
          <KVRow label="CheckSum" value={<>
            <HexVal n={optional_header.checksum}/>
            {optional_header.checksum > 0 && (
              <Badge variant={optional_header.checksum_valid ? 'green' : 'red'} >
                {optional_header.checksum_valid ? '✓ Valid' : '✗ Invalid'}
              </Badge>
            )}
          </>}/>
          <KVRow label="Subsystem" value={`${optional_header.subsystem_str} (${optional_header.subsystem})`}/>
          <KVRow label="DllCharacteristics" value={<HexVal n={optional_header.dll_characteristics} width={4}/>}/>
          <div className="mt-2 flex flex-wrap gap-1">
            {optional_header.dll_characteristics_flags.map(f => <Badge key={f}>{f}</Badge>)}
          </div>
          <KVRow label="SizeOfStackReserve" value={<HexVal n={optional_header.size_of_stack_reserve} width={16}/>}/>
          <KVRow label="SizeOfStackCommit" value={<HexVal n={optional_header.size_of_stack_commit} width={16}/>}/>
          <KVRow label="SizeOfHeapReserve" value={<HexVal n={optional_header.size_of_heap_reserve} width={16}/>}/>
          <KVRow label="SizeOfHeapCommit" value={<HexVal n={optional_header.size_of_heap_commit} width={16}/>}/>
          <KVRow label="NumberOfRvaAndSizes" value={optional_header.number_of_rva_and_sizes}/>
        </div>
      )}

      {tab === 'datadirs' && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-slate-600 border-b border-white/10">
                <th className="text-left py-1.5 pr-4">Directory</th>
                <th className="text-right py-1.5 pr-4">RVA</th>
                <th className="text-right py-1.5">Size</th>
              </tr>
            </thead>
            <tbody>
              {optional_header.data_directories.map((dd, i) => (
                <tr key={i} className={cn(
                  'border-b border-white/5 hover:bg-white/3 transition-colors',
                  dd.rva === 0 ? 'opacity-30' : ''
                )}>
                  <td className="py-1 pr-4 text-slate-300">{dd.name}</td>
                  <td className="py-1 pr-4 text-cyan-400 text-right">{formatHex(dd.rva)}</td>
                  <td className="py-1 text-slate-400 text-right">{formatHex(dd.size)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'rich' && (
        <div className="space-y-3">
          {!rich_header.present ? (
            <div className="text-slate-500 text-xs italic">No Rich header found</div>
          ) : (
            <>
              <div className="space-y-0.5">
                <KVRow label="XOR Key" value={<HexVal n={rich_header.xor_key}/>}/>
                <KVRow label="Checksum" value={<>
                  <HexVal n={rich_header.checksum}/>
                  <Badge variant={rich_header.checksum_valid ? 'green' : 'red'}>
                    {rich_header.checksum_valid ? '✓ Valid' : '✗ Mismatch'}
                  </Badge>
                </>}/>
              </div>
              <div className="overflow-x-auto mt-2">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="text-slate-600 border-b border-white/10">
                      <th className="text-left py-1.5 pr-4">Product</th>
                      <th className="text-right py-1.5 pr-4">ProdID</th>
                      <th className="text-right py-1.5 pr-4">BuildID</th>
                      <th className="text-right py-1.5">Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rich_header.entries.map((e, i) => (
                      <tr key={i} className="border-b border-white/5 hover:bg-white/3">
                        <td className="py-1 pr-4 text-slate-300">{e.product_name}</td>
                        <td className="py-1 pr-4 text-cyan-400 text-right">{formatHex(e.product_id, 4)}</td>
                        <td className="py-1 pr-4 text-slate-400 text-right">{formatHex(e.build_id, 4)}</td>
                        <td className="py-1 text-yellow-400 text-right">{e.use_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// Sections Panel
function SectionsPanel() {
  const { peInfo, setActivePanel, setDisasmRva, setHexRva } = useStore();
  if (!peInfo) return null;
  const [selected, setSelected] = useState<SectionInfo | null>(null);

  return (
    <div className="space-y-3">
      <div className="overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="text-slate-600 border-b border-white/10">
              <th className="text-left py-2 pr-3">Name</th>
              <th className="text-right py-2 pr-3">VirtAddr</th>
              <th className="text-right py-2 pr-3">VirtSize</th>
              <th className="text-right py-2 pr-3">RawOff</th>
              <th className="text-right py-2 pr-3">RawSize</th>
              <th className="py-2 pr-3 text-center">Entropy</th>
              <th className="py-2 pr-3 text-center">Flags</th>
              <th className="py-2 text-center">Actions</th>
            </tr>
          </thead>
          <tbody>
            {peInfo.sections.map((s, i) => (
              <tr
                key={i}
                onClick={() => setSelected(s === selected ? null : s)}
                className={cn(
                  'border-b border-white/5 cursor-pointer transition-colors',
                  selected === s ? 'bg-cyan-500/10' : 'hover:bg-white/3',
                  s.has_rwx ? 'bg-red-950/20' : ''
                )}
              >
                <td className="py-1.5 pr-3 text-slate-200 font-semibold">{s.name || '(unnamed)'}</td>
                <td className="py-1.5 pr-3 text-cyan-400 text-right">{formatHex(s.virtual_address)}</td>
                <td className="py-1.5 pr-3 text-slate-400 text-right">{formatHex(s.virtual_size)}</td>
                <td className="py-1.5 pr-3 text-slate-400 text-right">{formatHex(s.raw_offset)}</td>
                <td className="py-1.5 pr-3 text-slate-400 text-right">{formatHex(s.raw_size)}</td>
                <td className="py-1.5 pr-3">
                  <EntropyBar value={s.entropy} />
                </td>
                <td className="py-1.5 pr-3 text-center">
                  <div className="flex justify-center gap-0.5">
                    <span className={cn('text-[9px] px-0.5 rounded', s.is_readable ? 'text-green-400' : 'text-slate-700')}>R</span>
                    <span className={cn('text-[9px] px-0.5 rounded', s.is_writable ? 'text-yellow-400' : 'text-slate-700')}>W</span>
                    <span className={cn('text-[9px] px-0.5 rounded', s.is_executable ? 'text-red-400' : 'text-slate-700')}>X</span>
                    {s.has_rwx && <span className="text-[9px] text-red-400 ml-0.5">⚠</span>}
                    {s.raw_beyond_eof && <span className="text-[9px] text-orange-400">EOF</span>}
                  </div>
                </td>
                <td className="py-1.5 text-center">
                  <div className="flex justify-center gap-1">
                    {s.is_executable && (
                      <button
                        onClick={e => { e.stopPropagation(); setDisasmRva(s.virtual_address); setActivePanel('disasm'); }}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-purple-900/40 text-purple-400 hover:bg-purple-800/40 border border-purple-700/40"
                      >Disasm</button>
                    )}
                    <button
                      onClick={e => { e.stopPropagation(); setHexRva(s.virtual_address); setActivePanel('hexview'); }}
                      className="text-[10px] px-1.5 py-0.5 rounded bg-blue-900/40 text-blue-400 hover:bg-blue-800/40 border border-blue-700/40"
                    >Hex</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="bg-slate-900/60 rounded-lg border border-cyan-500/20 p-3">
          <h4 className="text-xs text-cyan-400 font-semibold mb-2">Section: {selected.name}</h4>
          <div className="grid grid-cols-2 gap-x-6 gap-y-0.5">
            <KVRow label="MD5" value={selected.md5} copy={selected.md5}/>
            <KVRow label="SHA-256" value={<span className="truncate block w-48">{selected.sha256}</span>} copy={selected.sha256}/>
            <KVRow label="Characteristics" value={<HexVal n={selected.characteristics}/>}/>
            <KVRow label="Entropy" value={selected.entropy.toFixed(6)}/>
          </div>
          <div className="mt-2 flex flex-wrap gap-1">
            {selected.characteristics_flags.map(f => <Badge key={f}>{f}</Badge>)}
          </div>
        </div>
      )}
    </div>
  );
}

// Imports Panel
function ImportsPanel() {
  const { peInfo, setActivePanel, setDisasmRva } = useStore();
  if (!peInfo) return null;
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [search, setSearch] = useState('');

  const toggle = (i: number) => setExpanded(prev => {
    const n = new Set(prev);
    n.has(i) ? n.delete(i) : n.add(i);
    return n;
  });

  const filtered = peInfo.imports.filter(d =>
    !search ||
    d.name.toLowerCase().includes(search.toLowerCase()) ||
    d.functions.some(f => f.name.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="space-y-2">
      <input
        value={search} onChange={e => setSearch(e.target.value)}
        placeholder="Search DLL or function…"
        className="w-full bg-slate-900 border border-white/10 rounded px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500/50"
      />
      <div className="text-xs text-slate-600">
        {peInfo.imports.length} DLLs · {peInfo.import_count} functions
      </div>
      <div className="space-y-1">
        {filtered.map((dll, i) => (
          <div key={i} className="rounded-md border border-white/8 overflow-hidden">
            <button
              onClick={() => toggle(i)}
              className="w-full flex items-center gap-2 px-3 py-2 text-left bg-slate-900/60 hover:bg-slate-800/60 transition-colors"
            >
              <ChevronRight size={12} className={cn('text-slate-500 transition-transform', expanded.has(i) && 'rotate-90')} />
              <span className="text-sm text-yellow-300 font-mono">{dll.name}</span>
              <span className="text-xs text-slate-600 ml-1">({dll.functions.length} functions)</span>
              {dll.is_bound && <Badge variant="blue">Bound</Badge>}
              <span className="ml-auto text-[10px] text-slate-600">{dll.time_date_stamp ? new Date(dll.time_date_stamp * 1000).getFullYear() : ''}</span>
            </button>
            {expanded.has(i) && (
              <div className="border-t border-white/5 max-h-64 overflow-y-auto pe-scrollbar">
                {dll.functions
                  .filter(f => !search || f.name.toLowerCase().includes(search.toLowerCase()))
                  .map((fn, j) => (
                    <div key={j} className="flex items-center gap-2 px-4 py-1 hover:bg-white/3 border-b border-white/3 text-xs font-mono">
                      <span className="text-slate-600 w-6 text-right">{j+1}</span>
                      <span className={cn('flex-1', fn.by_ordinal ? 'text-slate-500' : 'text-slate-300')}>
                        {fn.name || '(unnamed)'}
                      </span>
                      {fn.by_ordinal && <span className="text-slate-600">#{fn.ordinal}</span>}
                      <span className="text-cyan-700">{formatHex(fn.thunk_rva)}</span>
                      {fn.is_bound && <span className="text-slate-600">{formatHex(fn.bound_address, 16)}</span>}
                    </div>
                  ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {peInfo.delay_imports.length > 0 && (
        <div className="mt-4">
          <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-2">
            Delay Imports ({peInfo.delay_imports.length})
          </h4>
          {peInfo.delay_imports.map((dll, i) => (
            <div key={i} className="rounded border border-white/8 mb-1 bg-slate-900/40 px-3 py-2">
              <span className="text-yellow-300/70 font-mono text-sm">{dll.name}</span>
              <span className="text-slate-600 text-xs ml-2">({dll.functions.length})</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Exports Panel
function ExportsPanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;
  const exp = peInfo.exports;
  const [search, setSearch] = useState('');
  if (!exp.present) return (
    <div className="text-slate-500 text-sm italic text-center py-8">No exports directory</div>
  );

  const filtered = exp.functions.filter(f =>
    !search ||
    f.name.toLowerCase().includes(search.toLowerCase()) ||
    f.ordinal.toString().includes(search)
  );

  return (
    <div className="space-y-3">
      <div className="space-y-0.5 bg-slate-900/60 rounded-lg border border-white/10 p-3">
        <KVRow label="DLL Name" value={exp.name} copy={exp.name}/>
        <KVRow label="Ordinal Base" value={exp.ordinal_base}/>
        <KVRow label="NumberOfFunctions" value={exp.number_of_functions}/>
        <KVRow label="NumberOfNames" value={exp.number_of_names}/>
        <KVRow label="TimeDateStamp" value={exp.time_date_stamp ? new Date(exp.time_date_stamp*1000).toISOString() : '0'}/>
      </div>
      <input
        value={search} onChange={e => setSearch(e.target.value)}
        placeholder="Search export…"
        className="w-full bg-slate-900 border border-white/10 rounded px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500/50"
      />
      <div className="overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="text-slate-600 border-b border-white/10">
              <th className="text-right py-1.5 pr-4">Ordinal</th>
              <th className="text-left py-1.5 pr-4">Name</th>
              <th className="text-right py-1.5 pr-4">RVA</th>
              <th className="text-left py-1.5">Forwarder</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((fn, i) => (
              <tr key={i} className="border-b border-white/5 hover:bg-white/3">
                <td className="py-1 pr-4 text-yellow-400 text-right">{fn.ordinal}</td>
                <td className="py-1 pr-4 text-slate-300">{fn.name || <span className="text-slate-600 italic">no name</span>}</td>
                <td className="py-1 pr-4 text-cyan-400 text-right">{formatHex(fn.address)}</td>
                <td className="py-1 text-slate-500">{fn.is_forwarder ? fn.forwarder_string : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Disasm Panel
function DisasmPanel() {
  const { peInfo, sessionId, disasmRva, setDisasmRva } = useStore();
  const [instructions, setInstructions] = useState<DisasmInstruction[]>([]);
  const [loading, setLoading] = useState(false);
  const [inputRva, setInputRva] = useState('');
  const [inputSize, setInputSize] = useState('1024');

  const load = useCallback(async (rva: number, size: number) => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const res = await disassemble(sessionId, rva, size, 2000);
      setInstructions(res.instructions);
    } catch(e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    if (peInfo && sessionId) {
      const epRva = peInfo.optional_header.address_of_entry_point;
      setInputRva(formatHex(epRva));
      setDisasmRva(epRva);
      load(epRva, 1024);
    }
  }, [peInfo, sessionId]);

  const handleGo = () => {
    const rva = parseInt(inputRva, 16) || parseInt(inputRva, 10) || 0;
    const size = parseInt(inputSize) || 1024;
    setDisasmRva(rva);
    load(rva, size);
  };

  return (
    <div className="flex flex-col h-full space-y-2">
      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-slate-600 font-mono">RVA</span>
        <input value={inputRva} onChange={e => setInputRva(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleGo()}
          className="bg-slate-900 border border-white/10 rounded px-2 py-1 text-xs font-mono text-cyan-400 w-28 focus:outline-none focus:border-cyan-500/50"
          placeholder="0x1000"
        />
        <span className="text-xs text-slate-600 font-mono">Size</span>
        <input value={inputSize} onChange={e => setInputSize(e.target.value)}
          className="bg-slate-900 border border-white/10 rounded px-2 py-1 text-xs font-mono text-slate-300 w-20 focus:outline-none focus:border-cyan-500/50"
        />
        <button onClick={handleGo}
          className="px-3 py-1 bg-cyan-500/15 text-cyan-400 rounded border border-cyan-500/30 text-xs hover:bg-cyan-500/25 transition-colors"
        >Go</button>
        <button onClick={() => peInfo && load(peInfo.optional_header.address_of_entry_point, 1024)}
          className="px-2 py-1 text-xs text-slate-500 hover:text-slate-300 border border-white/10 rounded"
        >EP</button>
        <div className="flex gap-1 ml-auto">
          {[['call','#c084fc'],['jmp/jcc','#60a5fa'],['ret','#f87171'],['nop','#4b5563'],['mov','#94a3b8']].map(([l,c]) => (
            <span key={l} className="text-[10px] font-mono" style={{color: c as string}}>■ {l}</span>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"/>
        </div>
      ) : (
        <div className="overflow-auto flex-1 pe-scrollbar">
          <table className="w-full text-xs font-mono select-text">
            <thead className="sticky top-0 bg-slate-950">
              <tr className="text-slate-700 border-b border-white/10">
                <th className="text-left py-1 pr-4 w-24">Address</th>
                <th className="text-left py-1 pr-4 w-32">Bytes</th>
                <th className="text-left py-1 pr-2 w-20">Mnemonic</th>
                <th className="text-left py-1">Operands</th>
              </tr>
            </thead>
            <tbody>
              {instructions.map((insn, i) => (
                <tr
                  key={i}
                  className={cn(
                    'border-b border-white/3 hover:bg-white/3 transition-colors',
                    insn.is_ret ? 'bg-red-950/10' : ''
                  )}
                >
                  <td className="py-0.5 pr-4 text-slate-500">
                    {formatHex(insn.address, peInfo?.optional_header.is_64bit ? 16 : 8)}
                  </td>
                  <td className="py-0.5 pr-4 text-slate-700 tracking-wider">{insn.bytes}</td>
                  <td className="py-0.5 pr-2 font-semibold" style={{ color: instrColor(insn.color_class) }}>
                    {insn.mnemonic}
                    {insn.is_privileged && <span className="text-red-400 ml-1">!</span>}
                  </td>
                  <td className="py-0.5">
                    <span style={{ color: insn.color_class === 'mov' ? '#94a3b8' : instrColor(insn.color_class) }}>
                      {insn.operands}
                    </span>
                    {insn.branch_target && (
                      <button
                        onClick={() => {
                          const rva = parseInt(insn.branch_target, 16) - (peInfo?.optional_header.image_base || 0);
                          if (rva > 0) { setInputRva(formatHex(rva)); load(rva, 1024); }
                        }}
                        className="ml-2 text-cyan-600 hover:text-cyan-400 text-[10px]"
                      >→</button>
                    )}
                    {insn.is_nop && <span className="text-slate-700 ml-1">; nop</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// Hex View Panel
function HexViewPanel() {
  const { peInfo, sessionId, hexRva, setHexRva } = useStore();
  const [rows, setRows] = useState<Array<{offset: number; hex: string; ascii: string}>>([]);
  const [loading, setLoading] = useState(false);
  const [inputRva, setInputRva] = useState('0');
  const [inputSize, setInputSize] = useState('512');
  const [highlight, setHighlight] = useState<Set<number>>(new Set());

  const load = useCallback(async (rva: number, size: number) => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const data = await hexDump(sessionId, rva, size);
      setRows(data);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [sessionId]);

  useEffect(() => {
    if (hexRva !== undefined) {
      setInputRva(formatHex(hexRva));
      load(hexRva, 512);
    }
  }, [hexRva]);

  const handleGo = () => {
    const rva = parseInt(inputRva, 16) || parseInt(inputRva, 10) || 0;
    const size = parseInt(inputSize) || 512;
    setHexRva(rva);
    load(rva, size);
  };

  return (
    <div className="space-y-2 flex flex-col h-full">
      <div className="flex items-center gap-2">
        <span className="text-xs text-slate-600 font-mono">RVA/Offset</span>
        <input value={inputRva} onChange={e => setInputRva(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleGo()}
          className="bg-slate-900 border border-white/10 rounded px-2 py-1 text-xs font-mono text-cyan-400 w-28 focus:outline-none focus:border-cyan-500/50"
        />
        <span className="text-xs text-slate-600 font-mono">Size</span>
        <input value={inputSize} onChange={e => setInputSize(e.target.value)}
          className="bg-slate-900 border border-white/10 rounded px-2 py-1 text-xs font-mono text-slate-300 w-20 focus:outline-none focus:border-cyan-500/50"
        />
        <button onClick={handleGo}
          className="px-3 py-1 bg-cyan-500/15 text-cyan-400 rounded border border-cyan-500/30 text-xs hover:bg-cyan-500/25 transition-colors"
        >Go</button>
      </div>
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"/>
        </div>
      ) : (
        <div className="overflow-auto flex-1 pe-scrollbar">
          <table className="w-full text-xs font-mono select-text">
            <thead className="sticky top-0 bg-slate-950">
              <tr className="text-slate-700 border-b border-white/10">
                <th className="text-left py-1 pr-4 w-24">Offset</th>
                <th className="text-left py-1 pr-4">Hex (16 bytes)</th>
                <th className="text-left py-1">ASCII</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={i} className="border-b border-white/3 hover:bg-white/3 group">
                  <td className="py-0.5 pr-4 text-slate-600">{formatHex(row.offset)}</td>
                  <td className="py-0.5 pr-4">
                    <span className="text-slate-400 tracking-widest">{row.hex}</span>
                  </td>
                  <td className="py-0.5">
                    <span className="text-green-600/80 tracking-widest">{row.ascii}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// Strings Panel
function StringsPanel() {
  const { sessionId, peInfo, stringFilter, stringEncoding, stringQuery,
          setStringFilter, setStringEncoding, setStringQuery } = useStore();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(0);
  const LIMIT = 200;

  const load = useCallback(async (offset = 0) => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const res = await getStrings(sessionId, {
        filter: stringFilter, encoding: stringEncoding, q: stringQuery,
        limit: LIMIT, offset
      });
      setData(res);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, [sessionId, stringFilter, stringEncoding, stringQuery]);

  useEffect(() => { setPage(0); load(0); }, [stringFilter, stringEncoding, stringQuery]);
  useEffect(() => { if (sessionId) load(0); }, [sessionId]);

  const categories = ['Generic','URL','IP Address','Email','Registry','File Path'];

  return (
    <div className="space-y-2 flex flex-col h-full">
      <div className="flex flex-wrap items-center gap-2">
        <input value={stringQuery} onChange={e => setStringQuery(e.target.value)}
          placeholder="Search strings…"
          className="bg-slate-900 border border-white/10 rounded px-3 py-1.5 text-xs text-slate-300 font-mono flex-1 min-w-32 focus:outline-none focus:border-cyan-500/50"
        />
        <select value={stringFilter} onChange={e => setStringFilter(e.target.value)}
          className="bg-slate-900 border border-white/10 rounded px-2 py-1.5 text-xs text-slate-400 font-mono focus:outline-none">
          <option value="">All Categories</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select value={stringEncoding} onChange={e => setStringEncoding(e.target.value)}
          className="bg-slate-900 border border-white/10 rounded px-2 py-1.5 text-xs text-slate-400 font-mono focus:outline-none">
          <option value="">All Encodings</option>
          <option value="ASCII">ASCII</option>
          <option value="UTF-16LE">UTF-16LE</option>
        </select>
        {data && <span className="text-xs text-slate-600">{data.total.toLocaleString()} total</span>}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"/>
        </div>
      ) : (
        <div className="overflow-auto flex-1 pe-scrollbar">
          <table className="w-full text-xs font-mono">
            <thead className="sticky top-0 bg-slate-950">
              <tr className="text-slate-700 border-b border-white/10">
                <th className="text-left py-1 pr-3 w-24">Offset</th>
                <th className="text-left py-1 pr-3 w-20">Encoding</th>
                <th className="text-left py-1 pr-3 w-24">Category</th>
                <th className="text-left py-1">Value</th>
              </tr>
            </thead>
            <tbody>
              {data?.strings.map((s: any, i: number) => (
                <tr key={i} className="border-b border-white/3 hover:bg-white/3 group">
                  <td className="py-0.5 pr-3 text-slate-600">{formatHex(s.offset)}</td>
                  <td className="py-0.5 pr-3">
                    <Badge variant={s.encoding === 'UTF-16LE' ? 'purple' : 'default'}>{s.encoding}</Badge>
                  </td>
                  <td className="py-0.5 pr-3">
                    <Badge variant={
                      s.category === 'URL' ? 'blue' :
                      s.category === 'IP Address' ? 'orange' :
                      s.category === 'Registry' ? 'yellow' :
                      s.category === 'Email' ? 'purple' :
                      s.category === 'File Path' ? 'green' : 'default'
                    }>{s.category}</Badge>
                  </td>
                  <td className="py-0.5 text-slate-300 max-w-0">
                    <div className="flex items-center gap-1">
                      <span className="truncate">{s.value}</span>
                      <CopyButton text={s.value} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && data.total > LIMIT && (
        <div className="flex items-center gap-2 pt-1">
          <button onClick={() => { const p = page - 1; setPage(p); load(p * LIMIT); }}
            disabled={page === 0}
            className="px-2 py-0.5 text-xs rounded border border-white/10 text-slate-400 disabled:opacity-30">
            ‹ Prev
          </button>
          <span className="text-xs text-slate-600">{page+1} / {Math.ceil(data.total/LIMIT)}</span>
          <button onClick={() => { const p = page + 1; setPage(p); load(p * LIMIT); }}
            disabled={(page+1)*LIMIT >= data.total}
            className="px-2 py-0.5 text-xs rounded border border-white/10 text-slate-400 disabled:opacity-30">
            Next ›
          </button>
        </div>
      )}
    </div>
  );
}

// YARA Panel
function YaraPanel() {
  const { sessionId, yaraRules, setYaraRules } = useStore();
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [useBuiltin, setUseBuiltin] = useState(true);

  const runScan = async () => {
    if (!sessionId) return;
    setLoading(true); setError('');
    try {
      const res = await scanYara(sessionId, useBuiltin ? '' : yaraRules);
      setResult(res);
    } catch(e: any) {
      setError(e?.response?.data?.error || e?.message || 'Scan failed');
    } finally { setLoading(false); }
  };

  return (
    <div className="space-y-3 flex flex-col h-full">
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
          <input type="checkbox" checked={useBuiltin} onChange={e => setUseBuiltin(e.target.checked)}
            className="accent-cyan-500"/>
          Use built-in rules (malware detection)
        </label>
        <button onClick={runScan} disabled={loading || !sessionId}
          className="ml-auto px-4 py-1.5 bg-cyan-500/15 text-cyan-400 rounded border border-cyan-500/30 text-xs hover:bg-cyan-500/25 transition-colors disabled:opacity-40 flex items-center gap-2">
          {loading ? <><div className="w-3 h-3 border border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"/>Scanning…</> : <><Zap size={12}/>Scan</>}
        </button>
      </div>

      {!useBuiltin && (
        <textarea
          value={yaraRules} onChange={e => setYaraRules(e.target.value)}
          placeholder="Enter YARA rules here…"
          className="bg-slate-900 border border-white/10 rounded px-3 py-2 text-xs font-mono text-slate-300 h-48 resize-none focus:outline-none focus:border-cyan-500/50"
        />
      )}

      {error && <div className="text-red-400 text-xs px-2 py-1 bg-red-950/40 rounded border border-red-700/40">{error}</div>}

      {result && (
        <div className="space-y-2 flex-1 overflow-auto pe-scrollbar">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>{result.rule_count} rules loaded</span>
            <span>·</span>
            <span className={result.match_count > 0 ? 'text-orange-400' : 'text-green-400'}>
              {result.match_count} matches
            </span>
          </div>
          {result.matches.length === 0 && (
            <div className="text-green-400 text-sm text-center py-8">✓ No matches found</div>
          )}
          {result.matches.map((m: YaraMatch, i: number) => (
            <div key={i} className="bg-slate-900/60 rounded-lg border border-orange-500/20 p-3">
              <div className="flex items-start gap-2 mb-2">
                <AlertOctagon size={14} className="text-orange-400 mt-0.5 shrink-0"/>
                <div className="flex-1">
                  <span className="text-orange-300 font-semibold text-sm font-mono">{m.rule}</span>
                  {m.namespace && m.namespace !== 'default' && (
                    <span className="text-slate-600 text-xs ml-2">:{m.namespace}</span>
                  )}
                  {m.tags && <span className="text-slate-500 text-xs ml-2">tags: {m.tags}</span>}
                </div>
              </div>
              {m.meta.length > 0 && (
                <div className="mb-2 flex flex-wrap gap-1">
                  {m.meta.map((kv, j) => (
                    <span key={j} className="text-[10px] font-mono text-slate-500 bg-slate-800/60 px-1.5 py-0.5 rounded">{kv}</span>
                  ))}
                </div>
              )}
              {m.strings.length > 0 && (
                <div className="space-y-1">
                  {m.strings.map((sm, j) => (
                    <div key={j} className="flex items-center gap-2 text-xs font-mono bg-slate-900/40 rounded px-2 py-1 border border-white/5">
                      <span className="text-yellow-400 w-24 shrink-0">{sm.id}</span>
                      <span className="text-slate-600">{formatHex(sm.offset)}</span>
                      <span className="text-cyan-700">{sm.hex}</span>
                      <span className="text-green-700">{sm.ascii}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Anomalies Panel
function AnomaliesPanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;
  const [filter, setFilter] = useState<string>('');

  const filtered = peInfo.anomalies.filter(a =>
    !filter || a.severity === filter || a.category.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="space-y-2">
      <div className="flex gap-1">
        {['', 'CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s => (
          <button key={s} onClick={() => setFilter(s)}
            className={cn('px-2 py-0.5 rounded text-xs font-mono transition-colors',
              filter === s ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                          : 'text-slate-500 hover:text-slate-300 border border-transparent'
            )}>
            {s || 'All'}
          </button>
        ))}
        <span className="ml-auto text-xs text-slate-600">{filtered.length} / {peInfo.anomalies.length}</span>
      </div>
      <div className="space-y-1.5">
        {filtered.length === 0 && <div className="text-green-400 text-sm text-center py-8">✓ No anomalies</div>}
        {filtered.map((a, i) => (
          <div key={i} className={cn('px-3 py-2.5 rounded-md border text-xs', severityColor(a.severity))}>
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge sev={a.severity}/>
              <span className="text-slate-500">[{a.category}]</span>
              <span className="text-slate-200 font-semibold">{a.description}</span>
            </div>
            {a.detail && <p className="text-slate-500 pl-2 text-[11px]">{a.detail}</p>}
          </div>
        ))}
      </div>
    </div>
  );
}

// Entropy Panel
function EntropyPanel() {
  const { sessionId, peInfo } = useStore();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true);
    getEntropyMap(sessionId).then(setData).catch(console.error).finally(() => setLoading(false));
  }, [sessionId]);

  if (loading) return <div className="flex items-center justify-center py-16"><div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"/></div>;
  if (!data) return null;

  // Sample blocks for performance
  const blocks: EntropyBlock[] = data.blocks;
  const sampled = blocks.filter((_: any, i: number) => i % Math.max(1, Math.floor(blocks.length / 800)) === 0);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <span className="text-xs text-slate-500">Overall entropy:</span>
        <span className="font-mono text-sm" style={{ color: entropyColor(data.file_entropy) }}>
          {data.file_entropy.toFixed(4)}
        </span>
        <div className="flex gap-2 ml-auto text-[10px] font-mono">
          {[['> 7.2','#ef4444'],['> 6.5','#f97316'],['> 5.5','#eab308'],['> 3.5','#22c55e'],['≤ 3.5','#64748b']].map(([l,c]) => (
            <span key={l} style={{color:c as string}}>■ {l}</span>
          ))}
        </div>
      </div>

      <div className="bg-slate-900/60 rounded-lg border border-white/10 p-3">
        <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-3">Block Entropy (256-byte blocks)</h4>
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={sampled} margin={{top: 5, right: 5, left: -20, bottom: 0}}>
            <XAxis dataKey="offset" tick={{fill:'#475569',fontSize:9}}
              tickFormatter={v => formatHex(v)} />
            <YAxis domain={[0,8]} tick={{fill:'#475569',fontSize:9}} />
            <Tooltip contentStyle={{background:'#0f172a',border:'1px solid #334155',borderRadius:6}}
              labelStyle={{color:'#94a3b8', fontSize:10}}
              formatter={(v: number) => [v.toFixed(3),'Entropy']}
              labelFormatter={v => `Offset: ${formatHex(v)}`}
            />
            <ReferenceLine y={7} stroke="#ef444455" strokeDasharray="3 3" label={{value:'7.0',fill:'#ef4444',fontSize:9}}/>
            <ReferenceLine y={6.5} stroke="#f9731655" strokeDasharray="3 3"/>
            <Area type="monotone" dataKey="entropy" stroke="#06b6d4" strokeWidth={1}
              fill="url(#entropyGrad)" dot={false} />
            <defs>
              <linearGradient id="entropyGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.02}/>
              </linearGradient>
            </defs>
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="bg-slate-900/60 rounded-lg border border-white/10 p-3">
        <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-3">Section Entropy</h4>
        <div className="space-y-2">
          {data.sections.map((s: any, i: number) => (
            <div key={i} className="flex items-center gap-3">
              <span className="text-xs font-mono text-slate-300 w-20 truncate">{s.name || '(unnamed)'}</span>
              <span className="text-xs font-mono text-slate-600 w-24">{formatHex(s.rva)}</span>
              <div className="flex-1">
                <EntropyBar value={s.entropy}/>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// Generic detail panel for TLS, LoadConfig, CLR, Debug, Overlay
function DetailPanel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-slate-900/60 rounded-lg border border-white/10 p-4">
      <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-3">{title}</h4>
      {children}
    </div>
  );
}

function TlsPanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;
  const tls = peInfo.tls;
  if (!tls.present) return <div className="text-slate-500 text-sm italic text-center py-8">No TLS directory</div>;
  return (
    <div className="space-y-3">
      <DetailPanel title="TLS Directory">
        <div className="space-y-0.5">
          <KVRow label="StartAddressOfRawData" value={<HexVal n={tls.start_address_of_raw_data} width={16}/>}/>
          <KVRow label="EndAddressOfRawData" value={<HexVal n={tls.end_address_of_raw_data} width={16}/>}/>
          <KVRow label="AddressOfIndex" value={<HexVal n={tls.address_of_index} width={16}/>}/>
          <KVRow label="AddressOfCallBacks" value={<HexVal n={tls.address_of_callbacks} width={16}/>}/>
          <KVRow label="SizeOfZeroFill" value={tls.size_of_zero_fill}/>
          <KVRow label="Characteristics" value={<HexVal n={tls.characteristics}/>}/>
          <KVRow label="Callback Count" value={<span className={tls.callbacks.length > 0 ? 'text-orange-400' : ''}>{tls.callbacks.length}</span>}/>
        </div>
      </DetailPanel>
      {tls.callbacks.length > 0 && (
        <DetailPanel title="TLS Callbacks">
          {tls.callbacks.map((cb, i) => (
            <div key={i} className="font-mono text-xs text-orange-300 py-0.5">[{i}] <HexVal n={cb} width={16}/></div>
          ))}
        </DetailPanel>
      )}
    </div>
  );
}

function LoadConfigPanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;
  const lc = peInfo.load_config;
  if (!lc.present) return <div className="text-slate-500 text-sm italic text-center py-8">No Load Config directory</div>;
  return (
    <div className="space-y-3">
      <DetailPanel title="Load Configuration">
        <div className="space-y-0.5">
          <KVRow label="Has CFG" value={<Badge variant={lc.has_cfg ? 'green' : 'default'}>{lc.has_cfg ? '✓ Yes' : 'No'}</Badge>}/>
          <KVRow label="Has SEH Table" value={<Badge variant={lc.has_seh ? 'green' : 'default'}>{lc.has_seh ? `✓ (${lc.seh_handler_count} handlers)` : 'No'}</Badge>}/>
          <KVRow label="Has /GS Cookie" value={<Badge variant={lc.has_security_cookie ? 'green' : 'default'}>{lc.has_security_cookie ? '✓ Yes' : 'No'}</Badge>}/>
          <KVRow label="Security Cookie" value={<HexVal n={lc.security_cookie} width={16}/>}/>
          <KVRow label="Guard Flags" value={<HexVal n={lc.guard_flags}/>}/>
          <KVRow label="SEH Handler Count" value={lc.seh_handler_count}/>
        </div>
        {lc.guard_flags_decoded.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {lc.guard_flags_decoded.map(f => <Badge key={f} variant="green">{f}</Badge>)}
          </div>
        )}
      </DetailPanel>
    </div>
  );
}

function ClrPanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;
  const clr = peInfo.clr;
  if (!clr.present) return <div className="text-slate-500 text-sm italic text-center py-8">Not a .NET assembly</div>;
  return (
    <DetailPanel title=".NET CLR Header">
      <div className="space-y-0.5">
        <KVRow label="Runtime Version" value={`${clr.major_runtime_version}.${clr.minor_runtime_version}`}/>
        <KVRow label="Metadata RVA" value={<HexVal n={clr.metadata_rva}/>}/>
        <KVRow label="Flags" value={<HexVal n={clr.flags}/>}/>
        <KVRow label="Entry Point Token" value={<HexVal n={clr.entry_point_token}/>}/>
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        {clr.flags_decoded.map(f => <Badge key={f} variant="purple">{f}</Badge>)}
      </div>
    </DetailPanel>
  );
}

function DebugPanel() {
  const { peInfo } = useStore();
  if (!peInfo || !peInfo.debug.length) return <div className="text-slate-500 text-sm italic text-center py-8">No debug directory</div>;
  return (
    <div className="space-y-2">
      {peInfo.debug.map((d, i) => (
        <DetailPanel key={i} title={`Debug Entry ${i+1}: ${d.type_str}`}>
          <div className="space-y-0.5">
            <KVRow label="Type" value={<><Badge>{d.type_str}</Badge> <span className="text-slate-600 ml-1">({d.type})</span></>}/>
            <KVRow label="Size" value={formatSize(d.size)}/>
            <KVRow label="TimeDateStamp" value={d.time_stamp ? new Date(d.time_stamp*1000).toISOString() : '0'}/>
            {d.pdb_path && <KVRow label="PDB Path" value={d.pdb_path} copy={d.pdb_path}/>}
            {d.guid && <KVRow label="GUID" value={d.guid} copy={d.guid}/>}
            {d.age > 0 && <KVRow label="Age" value={d.age}/>}
          </div>
        </DetailPanel>
      ))}
    </div>
  );
}

function OverlayPanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;
  const ov = peInfo.overlay;
  if (!ov.present) return <div className="text-slate-500 text-sm italic text-center py-8">No overlay detected</div>;
  return (
    <DetailPanel title="Overlay Data">
      <div className="space-y-0.5 mb-3">
        <KVRow label="Offset" value={<HexVal n={ov.offset}/>}/>
        <KVRow label="Size" value={formatSize(ov.size)}/>
        <KVRow label="Entropy" value={<span style={{color: entropyColor(ov.entropy)}}>{ov.entropy.toFixed(4)}</span>}/>
        <KVRow label="Detected Format" value={<Badge variant={ov.detected_format !== 'Unknown' ? 'orange' : 'default'}>{ov.detected_format}</Badge>}/>
      </div>
      <div className="bg-slate-950 rounded px-3 py-2 font-mono text-[10px] text-slate-500 break-all">
        {ov.hex_preview}
      </div>
    </DetailPanel>
  );
}

function RelocationsPanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;
  return (
    <div className="space-y-2">
      <div className="text-xs text-slate-500">{peInfo.relocations_blocks} relocation blocks</div>
      <div className="overflow-auto max-h-96 pe-scrollbar">
        <table className="w-full text-xs font-mono">
          <thead className="sticky top-0 bg-slate-950">
            <tr className="text-slate-700 border-b border-white/10">
              <th className="text-left py-1.5 pr-4">Virtual Address</th>
              <th className="text-right py-1.5 pr-4">Block Size</th>
              <th className="text-right py-1.5">Entry Count</th>
            </tr>
          </thead>
          <tbody>
            {peInfo.relocations.map((r, i) => (
              <tr key={i} className="border-b border-white/5 hover:bg-white/3">
                <td className="py-1 pr-4 text-cyan-400">{formatHex(r.virtual_address)}</td>
                <td className="py-1 pr-4 text-slate-400 text-right">{r.size}</td>
                <td className="py-1 text-slate-400 text-right">{r.entry_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Resource Panel (tree view)
function ResourcesPanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;

  function RNode({ node, depth = 0 }: { node: any; depth?: number }) {
    const [open, setOpen] = useState(depth < 1);
    return (
      <div>
        <div
          onClick={() => node.is_directory && setOpen(o => !o)}
          className={cn(
            'flex items-center gap-1.5 py-0.5 px-1 rounded text-xs font-mono cursor-pointer hover:bg-white/5 transition-colors',
          )}
          style={{ paddingLeft: depth * 16 + 4 }}
        >
          {node.is_directory && (
            <ChevronRight size={10} className={cn('text-slate-600 transition-transform shrink-0', open && 'rotate-90')} />
          )}
          {!node.is_directory && <span className="w-2.5 shrink-0"/>}
          <span className={node.is_directory ? 'text-yellow-300' : 'text-slate-300'}>
            {node.name || `ID_${node.id}`}
          </span>
          {node.leaf && (
            <>
              <span className="text-slate-600">{formatSize(node.leaf.size)}</span>
              <Badge variant={node.leaf.entropy > 7 ? 'red' : 'default'}>{node.leaf.entropy.toFixed(2)}</Badge>
              {node.leaf.detected_format !== 'Unknown' && <Badge variant="blue">{node.leaf.detected_format}</Badge>}
            </>
          )}
        </div>
        {open && node.children?.map((c: any, i: number) => (
          <RNode key={i} node={c} depth={depth + 1} />
        ))}
      </div>
    );
  }

  return (
    <div className="overflow-auto pe-scrollbar">
      <RNode node={peInfo.resources} />
    </div>
  );
}

// Signature Panel
function SignaturePanel() {
  const { peInfo } = useStore();
  if (!peInfo) return null;
  const sig = peInfo.signature;
  if (!sig.signed_file) return (
    <div className="text-center py-8">
      <div className="text-slate-600 text-sm">File is not digitally signed</div>
    </div>
  );
  return (
    <DetailPanel title="Digital Signature">
      <div className="space-y-0.5">
        <KVRow label="Signed" value={<Badge variant="green">Yes</Badge>}/>
        <KVRow label="Verified" value={<Badge variant={sig.verified ? 'green' : 'red'}>{sig.verified ? '✓ Valid' : '✗ Invalid'}</Badge>}/>
        <KVRow label="Signer" value={sig.signer || 'N/A'}/>
        <KVRow label="Issuer" value={sig.issuer || 'N/A'}/>
      </div>
    </DetailPanel>
  );
}

// ─── Panel Map ────────────────────────────────────────────────────────────────
const PANELS: Record<PanelId, () => React.ReactNode> = {
  overview:    OverviewPanel,
  headers:     HeadersPanel,
  sections:    SectionsPanel,
  imports:     ImportsPanel,
  exports:     ExportsPanel,
  resources:   ResourcesPanel,
  disasm:      DisasmPanel,
  hexview:     HexViewPanel,
  strings:     StringsPanel,
  yara:        YaraPanel,
  anomalies:   AnomaliesPanel,
  entropy:     EntropyPanel,
  debug:       DebugPanel,
  tls:         TlsPanel,
  loadconfig:  LoadConfigPanel,
  clr:         ClrPanel,
  overlay:     OverlayPanel,
  signature:   SignaturePanel,
  rich:        () => { const { peInfo } = useStore(); return peInfo ? <HeadersPanel/> : null; },
  relocations: RelocationsPanel,
};

// ─── Upload Screen ────────────────────────────────────────────────────────────
function UploadScreen() {
  const { setSession, setPeInfo, setLoading, setError, loading, error } = useStore();
  const [isDragging, setIsDragging] = useState(false);

  const onDrop = useCallback(async (files: File[]) => {
    if (!files[0]) return;
    setLoading(true); setError(null);
    try {
      const result = await uploadFile(files[0]);
      if (!result.valid) { setError('Not a valid PE file'); setLoading(false); return; }
      const info = await analyzeSession(result.session_id);
      setSession(result.session_id);
      setPeInfo(info);
    } catch(e: any) {
      setError(e?.response?.data?.error || e?.message || 'Upload failed');
    } finally { setLoading(false); }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop, multiple: false, accept: { 'application/octet-stream': ['.exe','.dll','.sys','.ocx','.drv','.efi','.scr'] }
  });

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-8">
      <div className="w-full max-w-xl space-y-6">
        <div className="text-center space-y-2">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div className="w-10 h-10 bg-cyan-500/10 rounded-xl flex items-center justify-center border border-cyan-500/20">
              <Binary size={20} className="text-cyan-400"/>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">PE Visualizer</h1>
          </div>
          <p className="text-slate-500 text-sm">Static analysis for PE32/PE64 executables</p>
          <div className="flex justify-center gap-2 flex-wrap">
            {['Headers','Disassembly','Hex View','YARA','Entropy','Strings','Anomalies'].map(f => (
              <Badge key={f}>{f}</Badge>
            ))}
          </div>
        </div>

        <div
          {...getRootProps()}
          className={cn(
            'border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all',
            isDragActive
              ? 'border-cyan-500/60 bg-cyan-500/5'
              : 'border-slate-700 hover:border-slate-600 bg-slate-900/40 hover:bg-slate-900/60'
          )}
        >
          <input {...getInputProps()} />
          {loading ? (
            <div className="space-y-3">
              <div className="w-8 h-8 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin mx-auto"/>
              <p className="text-slate-400 text-sm">Analyzing PE…</p>
            </div>
          ) : (
            <div className="space-y-3">
              <Upload size={32} className="text-slate-600 mx-auto"/>
              <div>
                <p className="text-slate-300 text-sm">Drop PE file here or click to browse</p>
                <p className="text-slate-600 text-xs mt-1">.exe .dll .sys .ocx .drv .efi .scr — max 256 MB</p>
              </div>
            </div>
          )}
        </div>

        {error && (
          <div className="bg-red-950/40 border border-red-700/50 rounded-lg px-4 py-3 text-red-400 text-sm flex items-center gap-2">
            <AlertCircle size={14}/> {error}
          </div>
        )}

        <div className="text-center text-xs text-slate-700">
          Runs locally — files are not uploaded to any external server
        </div>
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const { sessionId, peInfo, activePanel, setActivePanel, sidebarOpen, toggleSidebar, reset } = useStore();

  if (!sessionId || !peInfo) return <UploadScreen/>;

  const navGroups = [
    { label: 'Analysis', items: [
      { id: 'overview' as PanelId, icon: Activity, label: 'Overview', badge: peInfo.anomalies.length || undefined },
      { id: 'anomalies' as PanelId, icon: AlertTriangle, label: 'Anomalies', badge: peInfo.anomalies.length },
      { id: 'entropy' as PanelId, icon: BarChart2, label: 'Entropy Map' },
      { id: 'strings' as PanelId, icon: FileSearch, label: 'Strings', badge: peInfo.string_count },
      { id: 'yara' as PanelId, icon: Shield, label: 'YARA Scanner' },
    ]},
    { label: 'PE Structure', items: [
      { id: 'headers' as PanelId, icon: FileCode2, label: 'Headers' },
      { id: 'sections' as PanelId, icon: Layers, label: 'Sections', badge: peInfo.sections.length },
      { id: 'imports' as PanelId, icon: Network, label: 'Imports', badge: peInfo.imports.length },
      { id: 'exports' as PanelId, icon: Database, label: 'Exports', badge: peInfo.exports.functions.length },
      { id: 'resources' as PanelId, icon: Grid3X3, label: 'Resources' },
    ]},
    { label: 'Code', items: [
      { id: 'disasm' as PanelId, icon: Terminal, label: 'Disassembler' },
      { id: 'hexview' as PanelId, icon: Hash, label: 'Hex View' },
    ]},
    { label: 'Directories', items: [
      { id: 'debug' as PanelId, icon: Bug, label: 'Debug', badge: peInfo.debug.length || undefined },
      { id: 'tls' as PanelId, icon: Zap, label: 'TLS', badge: peInfo.tls.callbacks.length || undefined },
      { id: 'loadconfig' as PanelId, icon: Lock, label: 'Load Config' },
      { id: 'clr' as PanelId, icon: Cpu, label: '.NET CLR', badge: peInfo.clr.present ? '✓' : undefined },
      { id: 'overlay' as PanelId, icon: HardDrive, label: 'Overlay', badge: peInfo.overlay.present ? '⚠' : undefined },
      { id: 'relocations' as PanelId, icon: RefreshCw, label: 'Relocations', badge: peInfo.relocations_blocks || undefined },
      { id: 'signature' as PanelId, icon: Shield, label: 'Signature', badge: peInfo.signature.signed_file ? '✓' : undefined },
    ]},
  ];

  const PanelComponent = PANELS[activePanel];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex overflow-hidden" style={{height:'100vh'}}>
      {/* Sidebar */}
      <AnimatePresence>
        {sidebarOpen && (
          <motion.aside
            initial={{x: -240, opacity: 0}}
            animate={{x: 0, opacity: 1}}
            exit={{x: -240, opacity: 0}}
            transition={{duration: 0.2}}
            className="w-56 shrink-0 bg-slate-950 border-r border-white/8 flex flex-col overflow-hidden"
          >
            {/* Logo */}
            <div className="p-3 border-b border-white/8 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Binary size={16} className="text-cyan-400"/>
                <span className="text-xs font-bold text-slate-300 tracking-wider">PE VISUALIZER</span>
              </div>
              <button onClick={toggleSidebar} className="text-slate-600 hover:text-slate-400 p-0.5">
                <X size={12}/>
              </button>
            </div>
            {/* File info */}
            <div className="px-3 py-2 border-b border-white/8">
              <p className="text-[10px] text-slate-600 truncate">{peInfo.file_path}</p>
              <div className="flex items-center gap-1 mt-0.5">
                <Badge variant={peInfo.pe_type === 'DLL' ? 'purple' : 'blue'}>{peInfo.pe_type}</Badge>
                <Badge variant={peInfo.optional_header.is_64bit ? 'green' : 'yellow'}>
                  {peInfo.optional_header.is_64bit ? '64-bit' : '32-bit'}
                </Badge>
                <span className="text-[10px] text-slate-600 ml-auto">{formatSize(peInfo.file_size)}</span>
              </div>
            </div>
            {/* Nav */}
            <div className="flex-1 overflow-y-auto pe-scrollbar py-2">
              {navGroups.map(group => (
                <div key={group.label} className="mb-3">
                  <p className="px-3 mb-1 text-[9px] font-semibold tracking-widest text-slate-700 uppercase">{group.label}</p>
                  <div className="space-y-0.5 px-1.5">
                    {group.items.map(item => (
                      <NavItem key={item.id} {...item} active={activePanel === item.id}
                        onClick={() => setActivePanel(item.id)} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
            {/* Close session */}
            <div className="p-2 border-t border-white/8">
              <button onClick={reset}
                className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-red-500/70 hover:text-red-400 hover:bg-red-950/30 rounded transition-colors">
                <Trash2 size={12}/> Close Session
              </button>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <header className="h-9 shrink-0 border-b border-white/8 flex items-center px-3 gap-3 bg-slate-950/90 backdrop-blur-sm">
          {!sidebarOpen && (
            <button onClick={toggleSidebar} className="text-slate-600 hover:text-slate-400 p-0.5">
              <Menu size={14}/>
            </button>
          )}
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <Binary size={12} className="text-cyan-500"/>
            <span className="text-slate-600">/</span>
            <span className="text-slate-400 font-mono">{navGroups.flatMap(g => g.items).find(i => i.id === activePanel)?.label || activePanel}</span>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className="text-[10px] text-slate-700 font-mono">{peInfo.hashes.md5.substring(0, 8)}…</span>
          </div>
        </header>

        {/* Panel */}
        <main className="flex-1 overflow-auto p-4 pe-scrollbar">
          <AnimatePresence mode="wait">
            <motion.div key={activePanel}
              initial={{opacity: 0, y: 6}}
              animate={{opacity: 1, y: 0}}
              exit={{opacity: 0, y: -6}}
              transition={{duration: 0.15}}
              className="h-full"
            >
              {PanelComponent ? <PanelComponent/> : null}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <style jsx global>{`
        .pe-scrollbar::-webkit-scrollbar { width: 4px; height: 4px; }
        .pe-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .pe-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 2px; }
        .pe-scrollbar::-webkit-scrollbar-thumb:hover { background: #475569; }
        * { scrollbar-width: thin; scrollbar-color: #334155 transparent; }
      `}</style>
    </div>
  );
}
