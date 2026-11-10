import React, { useState } from 'react';
import {
  WORKSPACE_FILES,
  WORKSPACE_TREE,
  CrateModuleNode,
  WorkspaceFile,
  generateWorkspaceBundleScript
} from '../data/workspaceData';
import {
  Folder,
  FileCode,
  Copy,
  Check,
  Download,
  Search,
  Terminal
} from 'lucide-react';

export const WorkspaceCodeView: React.FC = () => {
  const [selectedFileId, setSelectedFileId] = useState<string>('cargo-toml');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const activeFile: WorkspaceFile =
    WORKSPACE_FILES.find((f) => f.id === selectedFileId) || WORKSPACE_FILES[0];

  const codeLines = activeFile.code.split('\n');
  const matchingLineIndices = new Set<number>();
  if (searchQuery.trim().length > 0) {
    const q = searchQuery.toLowerCase();
    codeLines.forEach((line, idx) => {
      if (line.toLowerCase().includes(q)) {
        matchingLineIndices.add(idx);
      }
    });
  }

  const handleCopyCode = (file: WorkspaceFile) => {
    navigator.clipboard.writeText(file.code);
    setCopiedId(file.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleDownloadSingleFile = (file: WorkspaceFile) => {
    const blob = new Blob([file.code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const filename = file.path.split('/').pop() || 'file.rs';
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadFullWorkspace = () => {
    const script = generateWorkspaceBundleScript();
    const blob = new Blob([script], { type: 'text/x-shellscript;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'setup_ferrousx_workspace.sh';
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderTreeNode = (node: CrateModuleNode, depth = 0) => {
    const isSelected = node.fileId && node.fileId === selectedFileId;
    return (
      <div key={node.path} className="select-none">
        {node.type === 'file' ? (
          <button
            onClick={() => node.fileId && setSelectedFileId(node.fileId)}
            style={{ paddingLeft: `${depth * 14 + 10}px` }}
            className={`w-full flex items-center justify-between gap-2 py-2 pr-3 text-left text-xs font-mono rounded-lg transition-colors ${
              isSelected
                ? 'bg-amber-500/15 text-amber-300 font-semibold border border-amber-500/40'
                : 'text-slate-300 hover:bg-slate-800/70 hover:text-slate-100'
            }`}
          >
            <span className="flex items-center gap-2 truncate">
              <FileCode className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span className="truncate">{node.name}</span>
            </span>
          </button>
        ) : (
          <div
            style={{ paddingLeft: `${depth * 14 + 10}px` }}
            className="flex items-center gap-2 py-1.5 pr-3 text-xs font-mono text-slate-400"
          >
            <Folder className="w-3.5 h-3.5 text-slate-500 shrink-0" />
            <span className="font-semibold text-slate-300">{node.name}/</span>
          </div>
        )}
        {node.children && (
          <div className="space-y-0.5">
            {node.children.map((child) => renderTreeNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
        <div>
          <p className="text-xs font-mono text-amber-400 tracking-wide">
            02 &amp; 03. Cấu trúc Cargo Workspace &amp; Mã nguồn Khung lõi (Production-Ready Scaffolding)
          </p>
          <h2 className="mt-1 text-2xl sm:text-3xl font-bold text-slate-100 tracking-tight text-balance">
            Kiến trúc 5 Crate Độc lập &amp; Triển khai Mã nguồn Rust Cấp thấp
          </h2>
          <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
            Toàn bộ mã nguồn khung lõi được chia thành 5 crate chuyên biệt: <code className="text-slate-200">ferrousx-core</code>, <code className="text-slate-200">ferrousx-http</code>, <code className="text-slate-200">ferrousx-config</code>, <code className="text-slate-200">ferrousx-proxy</code> và <code className="text-slate-200">ferrousx-bin</code>. Chọn từng tệp bên dưới để xem chi tiết mã nguồn và chú giải kỹ thuật.
          </p>
        </div>

        <button
          onClick={handleDownloadFullWorkspace}
          className="flex items-center gap-2 px-4 py-2.5 text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-slate-950 rounded-lg transition-colors whitespace-nowrap shrink-0 self-start"
        >
          <Terminal className="w-4 h-4" />
          Tải Script Khởi tạo Workspace (.sh)
        </button>
      </div>

      {/* Quick Core File Selector Bar */}
      <div className="flex flex-wrap items-center gap-1.5 p-1.5 bg-slate-900 border border-slate-800 rounded-xl">
        {WORKSPACE_FILES.map((file) => {
          const active = file.id === selectedFileId;
          return (
            <button
              key={file.id}
              onClick={() => setSelectedFileId(file.id)}
              className={`px-3 py-2 text-xs font-mono rounded-lg transition-colors whitespace-nowrap shrink-0 ${
                active
                  ? 'bg-amber-500 text-slate-950 font-semibold'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-slate-100'
              }`}
            >
              {file.path.split('/').pop()}
            </button>
          );
        })}
      </div>

      {/* Main Split View: Left Tree & Crate Overview (4 Cols) | Right Code Viewer (8 Cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Sidebar: Cargo Workspace Tree + Key Highlights */}
        <div className="lg:col-span-4 space-y-6">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <h3 className="text-xs font-mono font-semibold text-slate-200">
                Cây thư mục Cargo Workspace
              </h3>
              <span className="text-xs font-mono text-slate-400">5 Crates · Edition 2024</span>
            </div>
            <div className="space-y-0.5">
              {WORKSPACE_TREE.map((node) => renderTreeNode(node, 0))}
            </div>
          </div>

          {/* Architectural Annotations for Active File */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
            <div>
              <span className="text-xs font-mono text-amber-400">
                Điểm nhấn Kiến trúc trong {activeFile.path.split('/').pop()}
              </span>
              <h4 className="mt-1 text-base font-bold text-slate-100">
                {activeFile.title}
              </h4>
              <p className="mt-1.5 text-xs text-slate-300 leading-relaxed">
                {activeFile.summary}
              </p>
            </div>

            <div className="space-y-3 pt-3 border-t border-slate-800">
              {activeFile.keyHighlights.map((hl, i) => (
                <div key={i} className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1">
                  <div className="text-xs font-semibold text-amber-300">
                    {hl.concept}
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 break-all">
                    {hl.lineHint}
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed pt-1">
                    {hl.detail}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Area: Full Source Code Viewer */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          {/* Code Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 bg-slate-950/80 border-b border-slate-800">
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-amber-400 font-semibold">{activeFile.path}</span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span className="text-slate-400 tabular-nums">{codeLines.length} dòng</span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {/* Search within file */}
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Tìm kiếm ký hiệu / hàm..."
                  className="pl-8 pr-3 py-1 text-xs font-mono bg-slate-900 border border-slate-700 rounded-md text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-amber-500 w-48"
                />
              </div>

              <button
                onClick={() => handleCopyCode(activeFile)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md transition-colors whitespace-nowrap shrink-0"
              >
                {copiedId === activeFile.id ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    Đã sao chép
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    Sao chép Mã
                  </>
                )}
              </button>

              <button
                onClick={() => handleDownloadSingleFile(activeFile)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md transition-colors whitespace-nowrap shrink-0"
              >
                <Download className="w-3.5 h-3.5" />
                Tải tệp
              </button>
            </div>
          </div>

          {/* Search Match Indicator */}
          {searchQuery.trim().length > 0 && (
            <div className="px-4 py-1.5 bg-slate-950 border-b border-slate-800 text-xs font-mono text-slate-400 flex items-center justify-between">
              <span>
                Tìm thấy <strong className="text-amber-400 tabular-nums">{matchingLineIndices.size}</strong> dòng khớp với &ldquo;{searchQuery}&rdquo;
              </span>
              <button
                onClick={() => setSearchQuery('')}
                className="text-slate-400 hover:text-slate-200 underline"
              >
                Xóa bộ lọc
              </button>
            </div>
          )}

          {/* Line-Numbered Code Surface */}
          <div className="overflow-x-auto max-h-[760px] overflow-y-auto p-4 font-mono text-xs leading-relaxed">
            <table className="w-full border-collapse">
              <tbody>
                {codeLines.map((line, index) => {
                  const isMatch = matchingLineIndices.has(index);
                  const isComment = line.trim().startsWith('//') || line.trim().startsWith('#');
                  return (
                    <tr
                      key={index}
                      className={`${
                        isMatch
                          ? 'bg-amber-500/20'
                          : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="select-none pr-4 text-right text-slate-600 tabular-nums w-10 align-top">
                        {index + 1}
                      </td>
                      <td
                        className={`whitespace-pre ${
                          isComment
                            ? 'text-slate-400 italic'
                            : 'text-slate-100'
                        }`}
                      >
                        {line || ' '}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
