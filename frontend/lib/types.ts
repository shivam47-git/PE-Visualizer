// ─── Core PE Types ─────────────────────────────────────────────────────────

export interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
  imphash: string;
}

export interface DosHeader {
  e_magic: number;
  e_cblp: number;
  e_cp: number;
  e_crlc: number;
  e_cparhdr: number;
  e_minalloc: number;
  e_maxalloc: number;
  e_ss: number;
  e_sp: number;
  e_csum: number;
  e_ip: number;
  e_cs: number;
  e_lfanew: number;
}

export interface RichEntry {
  build_id: number;
  product_id: number;
  use_count: number;
  product_name: string;
}

export interface RichHeader {
  present: boolean;
  xor_key: number;
  checksum: number;
  checksum_valid: boolean;
  raw_hex: string;
  entries: RichEntry[];
}

export interface FileHeader {
  machine: number;
  machine_str: string;
  number_of_sections: number;
  time_date_stamp: number;
  timestamp_str: string;
  pointer_to_symbol_table: number;
  number_of_symbols: number;
  size_of_optional_header: number;
  characteristics: number;
  characteristics_flags: string[];
}

export interface DataDirectory {
  name: string;
  rva: number;
  size: number;
}

export interface OptionalHeader {
  magic: number;
  is_64bit: boolean;
  linker_version: string;
  size_of_code: number;
  size_of_initialized_data: number;
  address_of_entry_point: number;
  base_of_code: number;
  image_base: number;
  section_alignment: number;
  file_alignment: number;
  os_version: string;
  image_version: string;
  subsystem_version: string;
  size_of_image: number;
  size_of_headers: number;
  checksum: number;
  checksum_valid: boolean;
  subsystem: number;
  subsystem_str: string;
  dll_characteristics: number;
  dll_characteristics_flags: string[];
  size_of_stack_reserve: number;
  size_of_stack_commit: number;
  size_of_heap_reserve: number;
  size_of_heap_commit: number;
  number_of_rva_and_sizes: number;
  data_directories: DataDirectory[];
}

export interface SectionInfo {
  name: string;
  virtual_size: number;
  virtual_address: number;
  raw_size: number;
  raw_offset: number;
  characteristics: number;
  characteristics_flags: string[];
  entropy: number;
  md5: string;
  sha256: string;
  is_executable: boolean;
  is_writable: boolean;
  is_readable: boolean;
  has_rwx: boolean;
  raw_beyond_eof: boolean;
}

export interface ImportedFunction {
  name: string;
  ordinal: number;
  by_ordinal: boolean;
  thunk_rva: number;
  iat_rva: number;
  is_bound: boolean;
  bound_address: number;
}

export interface ImportDLL {
  name: string;
  time_date_stamp: number;
  is_bound: boolean;
  functions: ImportedFunction[];
}

export interface DelayImportDLL {
  name: string;
  functions: ImportedFunction[];
}

export interface ExportedFunction {
  name: string;
  ordinal: number;
  address: number;
  is_forwarder: boolean;
  forwarder_string: string;
  has_name: boolean;
}

export interface ExportDirectory {
  present: boolean;
  name: string;
  ordinal_base: number;
  number_of_functions: number;
  number_of_names: number;
  time_date_stamp: number;
  functions: ExportedFunction[];
}

export interface ResourceLeaf {
  offset: number;
  size: number;
  code_page: number;
  type_name: string;
  entropy: number;
  detected_format: string;
  hex_preview: string;
}

export interface ResourceNode {
  name: string;
  id: number;
  is_named: boolean;
  is_directory: boolean;
  leaf?: ResourceLeaf;
  children: ResourceNode[];
}

export interface DebugEntry {
  type: number;
  type_str: string;
  time_stamp: number;
  major_version: number;
  minor_version: number;
  size: number;
  pdb_path: string;
  guid: string;
  age: number;
}

export interface TlsDirectory {
  present: boolean;
  start_address_of_raw_data: number;
  end_address_of_raw_data: number;
  address_of_index: number;
  address_of_callbacks: number;
  size_of_zero_fill: number;
  characteristics: number;
  callbacks: number[];
}

export interface LoadConfig {
  present: boolean;
  has_cfg: boolean;
  has_seh: boolean;
  has_security_cookie: boolean;
  security_cookie: number;
  guard_flags: number;
  guard_flags_decoded: string[];
  seh_handler_count: number;
}

export interface ClrHeader {
  present: boolean;
  major_runtime_version: number;
  minor_runtime_version: number;
  metadata_rva: number;
  metadata_size: number;
  flags: number;
  flags_decoded: string[];
  entry_point_token: number;
}

export interface OverlayInfo {
  present: boolean;
  offset: number;
  size: number;
  entropy: number;
  detected_format: string;
  hex_preview: string;
}

export interface Anomaly {
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  description: string;
  detail: string;
}

export interface ExtractedString {
  value: string;
  offset: number;
  encoding: string;
  section: string;
  category: string;
}

export interface Signature {
  signed_file: boolean;
  verified: boolean;
  signer: string;
  issuer: string;
}

export interface PEInfo {
  valid: boolean;
  error?: string;
  file_path: string;
  file_size: number;
  pe_type: string;
  file_entropy: number;
  import_count: number;
  export_count: number;
  string_count: number;
  timestamp_epoch: number;
  hashes: FileHashes;
  dos_header: DosHeader;
  rich_header: RichHeader;
  file_header: FileHeader;
  optional_header: OptionalHeader;
  sections: SectionInfo[];
  imports: ImportDLL[];
  delay_imports: DelayImportDLL[];
  exports: ExportDirectory;
  resources: ResourceNode;
  debug: DebugEntry[];
  tls: TlsDirectory;
  load_config: LoadConfig;
  exceptions_count: number;
  exceptions: Array<{begin: number; end: number; unwind: number}>;
  relocations_blocks: number;
  relocations: Array<{virtual_address: number; size: number; entry_count: number}>;
  clr: ClrHeader;
  overlay: OverlayInfo;
  signature: Signature;
  anomalies: Anomaly[];
  strings: ExtractedString[];
}

// ─── Disassembler Types ────────────────────────────────────────────────────

export interface DisasmOperand {
  type: string;
  text: string;
  value: number;
}

export interface DisasmInstruction {
  address: number;
  offset: number;
  size: number;
  mnemonic: string;
  operands: string;
  bytes: string;
  full: string;
  is_call: boolean;
  is_jump: boolean;
  is_ret: boolean;
  is_nop: boolean;
  is_privileged: boolean;
  branch_target: string;
  color_class: string;
  ops: DisasmOperand[];
}

export interface DisasmResult {
  rva: number;
  va: number;
  file_offset: number;
  size: number;
  instructions: DisasmInstruction[];
  hex: HexRow[];
}

// ─── Hex Dump ─────────────────────────────────────────────────────────────

export interface HexRow {
  offset: number;
  hex: string;
  ascii: string;
}

// ─── YARA ─────────────────────────────────────────────────────────────────

export interface YaraStringMatch {
  id: string;
  offset: number;
  hex: string;
  ascii: string;
}

export interface YaraMatch {
  rule: string;
  namespace: string;
  tags: string;
  meta: string[];
  strings: YaraStringMatch[];
}

export interface YaraScanResult {
  rule_count: number;
  match_count: number;
  matches: YaraMatch[];
}

// ─── Entropy ──────────────────────────────────────────────────────────────

export interface EntropyBlock {
  offset: number;
  size: number;
  entropy: number;
}

export interface EntropyMap {
  file_entropy: number;
  blocks: EntropyBlock[];
  sections: Array<{name: string; rva: number; size: number; entropy: number}>;
}

// ─── Session ──────────────────────────────────────────────────────────────

export interface SessionInfo {
  id: string;
  filename: string;
  size: number;
  pe_type: string;
}

export interface UploadResult {
  session_id: string;
  filename: string;
  file_size: number;
  pe_type: string;
  valid: boolean;
}

// ─── App State ────────────────────────────────────────────────────────────

export type PanelId =
  | 'overview'
  | 'headers'
  | 'sections'
  | 'imports'
  | 'exports'
  | 'resources'
  | 'disasm'
  | 'hexview'
  | 'strings'
  | 'yara'
  | 'anomalies'
  | 'entropy'
  | 'debug'
  | 'tls'
  | 'loadconfig'
  | 'clr'
  | 'overlay'
  | 'signature'
  | 'rich'
  | 'relocations';

export type Theme = 'dark' | 'light';
