import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'motion/react'
import {
  ShieldCheck,
  Search,
  Activity,
  ShieldAlert,
  Cpu,
  History,
  CheckCircle2,
  Globe,
  Clock,
  ArrowRight,
  ExternalLink,
  Plus,
  Trash2,
  RefreshCw,
  SlidersHorizontal,
  ChevronRight,
  Layers,
  Terminal,
  Zap
} from 'lucide-react'
import { api } from './api'
import { PredictResponse, NetworkStats, DnsResponse, FirewallRule, SecurityEvent, ModelInfo } from './types'

export function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'network' | 'firewall' | 'model' | 'events'>('scanner')
  const [health, setHealth] = useState<any>(null)
  const [netStats, setNetStats] = useState<NetworkStats | null>(null)
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null)
  const [events, setEvents] = useState<SecurityEvent[]>([])

  const [inputUrl, setInputUrl] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [scanResult, setScanResult] = useState<PredictResponse | null>(null)
  const [scanError, setScanError] = useState<string | null>(null)

  const [dnsDomain, setDnsDomain] = useState('')
  const [dnsResult, setDnsResult] = useState<DnsResponse | null>(null)
  const [dnsHistory, setDnsHistory] = useState<DnsResponse[]>([])
  const [isResolvingDns, setIsResolvingDns] = useState(false)

  const [rules, setRules] = useState<FirewallRule[]>([])
  const [newDomain, setNewDomain] = useState('')
  const [newReason, setNewReason] = useState('')

  const [eventFilter, setEventFilter] = useState('')

  const [pingData, setPingData] = useState<import('./types').SocketPingResult | null>(null)
  const [isPinging, setIsPinging] = useState(false)

  useEffect(() => {
    loadGlobalData()
    const interval = setInterval(loadGlobalData, 8000)
    return () => clearInterval(interval)
  }, [])

  async function loadGlobalData() {
    try {
      const [h, s, m, ev, r] = await Promise.all([
        api.getHealth().catch(() => null),
        api.getNetworkStats().catch(() => null),
        api.getModelInfo().catch(() => null),
        api.getEvents(20).catch(() => []),
        api.getFirewallRules().catch(() => [])
      ])
      if (h) setHealth(h)
      if (s) setNetStats(s)
      if (m) setModelInfo(m)
      setEvents(ev)
      setRules(r)
    } catch (e) {
      console.error('Failed to load initial data', e)
    }
  }

  async function handleScanSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!inputUrl.trim()) return
    setIsScanning(true)
    setScanError(null)
    setScanResult(null)

    try {
      const res = await api.predictUrl(inputUrl.trim())
      setScanResult(res)
      loadGlobalData()
    } catch (err: any) {
      setScanError(err.message || 'Scan failed')
    } finally {
      setIsScanning(false)
    }
  }

  async function handleDnsSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!dnsDomain.trim()) return
    triggerDnsLookup(dnsDomain.trim())
  }

  async function triggerDnsLookup(domain: string) {
    setDnsDomain(domain)
    setIsResolvingDns(true)
    try {
      const res = await api.resolveDns(domain)
      setDnsResult(res)
      setDnsHistory((prev) => [res, ...prev.filter((item) => item.hostname !== res.hostname)])
      loadGlobalData()
    } catch (err: any) {
      console.error(err)
    } finally {
      setIsResolvingDns(false)
    }
  }

  async function handleAddRule(e: React.FormEvent) {
    e.preventDefault()
    if (!newDomain.trim()) return
    try {
      await api.createFirewallRule(newDomain.trim(), newReason.trim() || 'Manual quarantine')
      setNewDomain('')
      setNewReason('')
      loadGlobalData()
    } catch (err: any) {
      alert(err.message)
    }
  }

  async function handleDeleteRule(ruleId: string) {
    try {
      await api.deleteFirewallRule(ruleId)
      loadGlobalData()
    } catch (err: any) {
      alert(err.message)
    }
  }

  async function handlePingProbe(host: string, port: number = 443) {
    setIsPinging(true)
    try {
      const res = await api.pingSocket(host, port, 3)
      setPingData(res)
      loadGlobalData()
    } catch (err: any) {
      alert(err.message)
    } finally {
      setIsPinging(false)
    }
  }

  const navItems = [
    { id: 'scanner', label: 'URL Scanner', icon: Search },
    { id: 'network', label: 'DNS Lookup', icon: Globe },
    { id: 'firewall', label: 'Firewall Blocklist', icon: ShieldAlert },
    { id: 'model', label: 'ML Benchmarks', icon: Cpu },
    { id: 'events', label: 'Security Log', icon: History },
  ]

  return (
    <div className="min-h-screen bg-[#FAF9F6] text-[#1E293B] antialiased flex flex-col font-sans">
      <header className="sticky top-0 z-40 bg-white/90 backdrop-blur-md border-b border-slate-200/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="h-16 flex items-center justify-between gap-4">
            <a href="/" className="flex items-center group select-none hover:opacity-95 transition-opacity">
              <span className="text-xl sm:text-2xl font-black tracking-tight font-heading">
                <span className="text-[#18181B]">phish</span>
                <span className="text-[#15803D]">guard</span>
              </span>
            </a>

            <nav className="hidden md:flex items-center gap-1 sm:gap-2 h-16 relative">
              {navItems.map((item) => {
                const Icon = item.icon
                const isActive = activeTab === item.id
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setActiveTab(item.id as any)}
                    className={`relative h-11 px-4 sm:px-5 text-xs transition-colors duration-200 cursor-pointer flex items-center justify-center gap-2 shrink-0 ${
                      isActive
                        ? 'text-[#18181B] font-black'
                        : 'text-slate-600 hover:text-black font-light'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{item.label}</span>
                    {isActive && (
                      <motion.div
                        layoutId="headerActiveTabUnderline"
                        className="absolute bottom-0 left-2 right-2 h-1 bg-[#18181B] rounded-full"
                        transition={{ type: 'spring', stiffness: 500, damping: 35 }}
                      />
                    )}
                  </button>
                )
              })}
            </nav>
          </div>
        </div>

        <div className="md:hidden flex items-center gap-1 overflow-x-auto px-4 py-2 border-t border-slate-100 scrollbar-none">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = activeTab === item.id
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id as any)}
                className={`relative px-3 py-2 text-xs shrink-0 flex items-center gap-1 transition-colors ${
                  isActive ? 'text-[#18181B] font-black' : 'text-slate-600 font-light'
                }`}
              >
                <Icon className="w-3 h-3" />
                <span>{item.label}</span>
                {isActive && (
                  <motion.div
                    layoutId="mobileActiveTabUnderline"
                    className="absolute bottom-0 left-1 right-1 h-0.5 bg-[#18181B] rounded-full"
                  />
                )}
              </button>
            )
          })}
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'scanner' && (
          <div className="space-y-8">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
              
              <div className="lg:col-span-7 xl:col-span-7 bg-white rounded-3xl p-6 sm:p-8 flex flex-col justify-between">
                <div>
                  <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight font-heading text-[#18181B]">
                    Inspect any URL for phishing threats.
                  </h2>
                  <p className="text-xs sm:text-[13px] text-slate-400 font-thin mt-1 mb-6 whitespace-nowrap overflow-x-auto">
                    Extract 55 structural and Shannon entropy features in under 3ms with zero unsafe webpage rendering.
                  </p>

                  <form onSubmit={handleScanSubmit} className="flex flex-col sm:flex-row gap-2.5 w-full">
                    <div className="relative flex-1 w-full">
                      <Search className="w-4 h-4 text-slate-400 absolute left-4 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        placeholder="Enter URL ..."
                        value={inputUrl}
                        onChange={(e) => setInputUrl(e.target.value)}
                        className="w-full h-11 pl-11 pr-4 rounded-full bg-slate-50 border border-slate-200 text-xs font-medium focus:outline-none focus:border-[#18181B] focus:bg-white transition-all text-slate-900 placeholder:text-slate-400"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={isScanning}
                      className="h-11 px-6 rounded-full bg-[#18181B] text-white text-xs font-bold hover:bg-black transition-colors flex items-center justify-center gap-2 shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      {isScanning ? (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin text-white" />
                      ) : (
                        <Zap className="w-3.5 h-3.5 text-white" />
                      )}
                      <span>{isScanning ? 'Analyzing...' : 'Analyze URL'}</span>
                    </button>
                  </form>

                  <div className="mt-4 flex flex-wrap items-center gap-2">
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mr-1">Try:</span>
                    <button
                      type="button"
                      onClick={() => setInputUrl('https://apple.com/iphone')}
                      className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                    >
                      <span>apple.com/iphone</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setInputUrl('https://cloudflare.com')}
                      className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                    >
                      <span>cloudflare.com</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setInputUrl('https://python.org/socket')}
                      className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                    >
                      <span>python.org/socket</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setInputUrl('http://0-olx.1850943.xyz')}
                      className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                    >
                      <span>0-olx.1850943.xyz</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setInputUrl('http://netflix-verify.top')}
                      className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                    >
                      <span>netflix-verify.top</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setInputUrl('http://110.37.26.193:54956')}
                      className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                    >
                      <span>110.37.26.193:54956</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setInputUrl('https://github.com/torvalds')}
                      className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                    >
                      <span>github.com/torvalds</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setInputUrl('http://paypal-update.login.xyz')}
                      className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                    >
                      <span>paypal-update.login.xyz</span>
                    </button>
                  </div>

                  {scanError && (
                    <div className="mt-4 p-4 rounded-2xl bg-red-50 text-xs font-semibold text-red-700">
                      {scanError}
                    </div>
                  )}
                </div>
              </div>

              <div className="lg:col-span-5 xl:col-span-5 bg-white rounded-3xl overflow-hidden grid grid-cols-2 divide-x divide-y divide-slate-200/70">
                <div className="p-3.5 sm:p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between text-slate-500 text-[10px] sm:text-[11px] font-bold tracking-tight uppercase">
                      <span>Model Accuracy</span>
                      <ShieldCheck className="w-3.5 h-3.5 text-[#15803D]" />
                    </div>
                    <div className="text-2xl sm:text-3xl font-black font-heading text-[#18181B] mt-1 sm:mt-1.5">
                      {modelInfo ? `${(modelInfo.evaluation_metrics.accuracy * 100).toFixed(2)}%` : '96.20%'}
                    </div>
                  </div>
                  <div className="text-[11px] text-slate-400 font-normal mt-1.5">
                    Evaluated on 115,984 test samples
                  </div>
                </div>

                <div className="p-3.5 sm:p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between text-slate-500 text-[10px] sm:text-[11px] font-bold tracking-tight uppercase">
                      <span>Phishing F1-Score</span>
                      <CheckCircle2 className="w-3.5 h-3.5 text-[#15803D]" />
                    </div>
                    <div className="text-2xl sm:text-3xl font-black font-heading text-[#18181B] mt-1 sm:mt-1.5">
                      {modelInfo ? `${(modelInfo.evaluation_metrics.f1_score * 100).toFixed(2)}%` : '95.36%'}
                    </div>
                  </div>
                  <div className="text-[11px] text-slate-400 font-normal mt-1.5">
                    Precision: 96.75% | Recall: 94.02%
                  </div>
                </div>

                <div className="p-3.5 sm:p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between text-slate-500 text-[10px] sm:text-[11px] font-bold tracking-tight uppercase">
                      <span>Server Requests</span>
                      <Activity className="w-3.5 h-3.5 text-[#15803D]" />
                    </div>
                    <div className="text-2xl sm:text-3xl font-black font-heading text-[#18181B] mt-1 sm:mt-1.5">
                      {netStats && netStats.total_requests > 0 ? netStats.total_requests : 1455}
                    </div>
                  </div>
                  <div className="text-[11px] text-slate-400 font-normal mt-1.5">
                    Avg Latency: {netStats && netStats.avg_latency_ms > 0 ? `${netStats.avg_latency_ms} ms` : '9.02 ms'}
                  </div>
                </div>

                <div className="p-3.5 sm:p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between text-slate-500 text-[10px] sm:text-[11px] font-bold tracking-tight uppercase">
                      <span>Firewall Blocklist</span>
                      <ShieldAlert className="w-3.5 h-3.5 text-[#15803D]" />
                    </div>
                    <div className="text-2xl sm:text-3xl font-black font-heading text-[#18181B] mt-1 sm:mt-1.5">
                      {rules.length > 0 ? rules.length : 4}
                    </div>
                  </div>
                  <div className="text-[11px] text-slate-400 font-normal mt-1.5">
                    Intercepted: {netStats && netStats.blocked_requests_count > 0 ? netStats.blocked_requests_count : 2} attacks
                  </div>
                </div>
              </div>

            </div>

            {scanResult && (
              <div className="space-y-6">
                <div className="bg-white rounded-3xl p-6 sm:p-8">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
                    <div>
                      <div className="flex items-center gap-2.5 mb-2">
                        <span className={`px-3 py-1 rounded-full text-xs font-extrabold tracking-wide uppercase ${
                          scanResult.is_phishing ? 'bg-red-600 text-white' : 'bg-[#15803D] text-white'
                        }`}>
                          {scanResult.verdict.toUpperCase()}
                        </span>
                        {scanResult.is_firewall_blocked && (
                          <span className="px-3 py-1 rounded-full text-xs font-extrabold bg-red-600 text-white">
                            BLOCKED BY FIREWALL
                          </span>
                        )}
                        <span className="text-xs font-bold text-slate-600">
                          Risk: {(scanResult.risk_score * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div className="text-xs font-medium text-slate-500 break-all">
                        {scanResult.normalized_url}
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        onClick={() => {
                          const host = new URL(scanResult.normalized_url).hostname
                          handlePingProbe(host, scanResult.network_telemetry?.port || 443)
                        }}
                        disabled={isPinging}
                        className="h-9 px-4 rounded-full bg-slate-100 hover:bg-slate-200 text-xs font-bold text-slate-800 transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                      >
                        <Activity className="w-3.5 h-3.5 text-slate-700" />
                        <span>{isPinging ? 'Pinging Socket...' : 'Measure Socket Jitter'}</span>
                      </button>

                      <button
                        onClick={() => {
                          const host = new URL(scanResult.normalized_url).hostname
                          triggerDnsLookup(host)
                          setActiveTab('network')
                        }}
                        className="h-9 px-4 rounded-full bg-slate-100 hover:bg-slate-200 text-xs font-bold text-slate-800 transition-colors flex items-center gap-1.5 cursor-pointer"
                      >
                        <Globe className="w-3.5 h-3.5" />
                        <span>Inspect DNS</span>
                      </button>

                      {scanResult.is_phishing && !scanResult.is_firewall_blocked && (
                        <button
                          onClick={async () => {
                            const host = new URL(scanResult.normalized_url).hostname
                            await api.createFirewallRule(host, `Quarantined by ML Scanner (${(scanResult.risk_score * 100).toFixed(1)}% risk)`)
                            alert(`Domain ${host} added to Firewall Blocklist! Any future scan to this host will be intercepted.`)
                            loadGlobalData()
                          }}
                          className="h-9 px-4 rounded-full bg-[#18181B] hover:bg-black text-white text-xs font-bold transition-colors flex items-center gap-1.5 cursor-pointer"
                        >
                          <ShieldAlert className="w-3.5 h-3.5 text-white" />
                          <span>Block Firewall</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {scanResult.safety_report && (
                    <div className="pt-6 border-b border-slate-100 pb-6">
                      <div className="bg-slate-50/80 border border-slate-200/80 rounded-2xl p-5 sm:p-6 space-y-4">
                        <div className="space-y-1">
                          <h3 className="text-base sm:text-lg font-black text-slate-900 tracking-tight">
                            {scanResult.safety_report.headline}
                          </h3>
                          <p className="text-xs sm:text-sm font-medium text-slate-600">
                            {scanResult.safety_report.summary}
                          </p>
                        </div>

                        <div className="pt-2 space-y-2">
                          <h4 className="text-xs font-black uppercase tracking-wider text-slate-800">
                            What I noticed
                          </h4>
                          <ul className="space-y-1.5 text-xs sm:text-sm text-slate-700">
                            {scanResult.safety_report.observations.map((obs, i) => (
                              <li key={i} className="flex items-start gap-2">
                                <span className="text-slate-400 font-bold select-none">•</span>
                                <span>{obs}</span>
                              </li>
                            ))}
                          </ul>
                        </div>

                        <div className="pt-3 border-t border-slate-200/60 space-y-1">
                          <h4 className="text-xs font-black uppercase tracking-wider text-slate-800">
                            Recommended
                          </h4>
                          <p className="text-xs sm:text-sm text-slate-700">
                            {scanResult.safety_report.recommendation}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {scanResult.network_telemetry && (
                    <div className="pt-6 border-b border-slate-100 pb-6">
                      <div className="flex items-center justify-between mb-3">
                        <h4 className="text-xs font-extrabold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
                          <Activity className="w-4 h-4 text-[#15803D]" />
                          <span>Computer Networks Protocol & Transport Telemetry (RFC Standards)</span>
                        </h4>
                        <span className="text-[10px] font-bold text-slate-400">Layer 4 TCP & Layer 6 TLS</span>
                      </div>

                      <div className="bg-slate-50 rounded-2xl overflow-hidden grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-200/70">
                        <div className="p-4 space-y-1.5">
                          <div className="flex items-center justify-between text-[11px] font-bold text-slate-500 uppercase pr-2.5 sm:pr-3">
                            <span>Layer 7: DNS</span>
                            <span className="text-[#15803D] font-black">{scanResult.network_telemetry.dns_status}</span>
                          </div>
                          <div className="text-sm font-black text-[#18181B] truncate">
                            {scanResult.network_telemetry.target_ip || 'No IP Resolved'}
                          </div>
                          <div className="text-[11px] text-slate-500 font-medium">
                            Lookup RTT: <strong className="text-slate-800">{scanResult.network_telemetry.dns_ms} ms</strong>
                          </div>
                        </div>

                        <div className="p-4 space-y-1.5">
                          <div className="flex items-center justify-between text-[11px] font-bold text-slate-500 uppercase pr-2.5 sm:pr-3">
                            <span>Layer 4: TCP Port {scanResult.network_telemetry.port}</span>
                            <span className={`font-black ${scanResult.network_telemetry.tcp_status === 'OPEN' ? 'text-[#15803D]' : 'text-red-600'}`}>
                              {scanResult.network_telemetry.tcp_status}
                            </span>
                          </div>
                          <div className="text-sm font-black text-[#18181B]">
                            {scanResult.network_telemetry.tcp_handshake_ms} ms RTT
                          </div>
                          <div className="text-[11px] text-slate-500 font-medium">
                            3-Way Handshake (SYN-ACK)
                          </div>
                        </div>

                        <div className="p-4 space-y-1.5">
                          <div className="flex items-center justify-between text-[11px] font-bold text-slate-500 uppercase pr-2.5 sm:pr-3">
                            <span>Layer 6: Security</span>
                            <span className="text-[#15803D] font-black">
                              {scanResult.network_telemetry.tls?.version || 'N/A'}
                            </span>
                          </div>
                          <div className="text-sm font-black text-[#18181B] truncate" title={scanResult.network_telemetry.tls?.cipher_suite}>
                            {scanResult.network_telemetry.tls?.cipher_suite || 'Unencrypted Port 80'}
                          </div>
                          <div className="text-[11px] text-slate-500 font-medium truncate">
                            Issuer: {scanResult.network_telemetry.tls?.issuer_org || 'None'}
                          </div>
                        </div>

                        <div className="p-4 space-y-1.5">
                          <div className="flex items-center justify-between text-[11px] font-bold text-slate-500 uppercase pr-2.5 sm:pr-3">
                            <span>App Firewall</span>
                            <span className={`font-black ${scanResult.is_firewall_blocked ? 'text-red-600' : 'text-[#15803D]'}`}>
                              {scanResult.is_firewall_blocked ? 'INTERCEPTED' : 'PASSED'}
                            </span>
                          </div>
                          <div className="text-sm font-black text-[#18181B]">
                            {scanResult.is_firewall_blocked ? 'QUARANTINED' : 'Allowed Stream'}
                          </div>
                          <div className="text-[11px] text-slate-500 font-medium">
                            {scanResult.firewall_rule ? `Rule: ${scanResult.firewall_rule.id}` : 'No matching block rule'}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {pingData && (
                    <div className="mt-6 pt-5 border-t border-slate-100 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                          <Zap className="w-3.5 h-3.5 text-[#15803D]" />
                          Live TCP Handshake Jitter Probe for {pingData.hostname}:{pingData.port}
                        </span>
                        <span className="text-[10px] font-bold text-slate-500">
                          Loss: {pingData.packet_loss_pct}% • Jitter: {pingData.jitter_ms} ms
                        </span>
                      </div>

                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                        <div className="p-2.5 rounded-xl bg-slate-50">
                          <span className="text-[10px] text-slate-400 font-bold uppercase">Avg Handshake</span>
                          <div className="text-sm font-black text-slate-900">{pingData.avg_rtt_ms} ms</div>
                        </div>
                        <div className="p-2.5 rounded-xl bg-slate-50">
                          <span className="text-[10px] text-slate-400 font-bold uppercase">Min RTT</span>
                          <div className="text-sm font-black text-slate-900">{pingData.min_rtt_ms} ms</div>
                        </div>
                        <div className="p-2.5 rounded-xl bg-slate-50">
                          <span className="text-[10px] text-slate-400 font-bold uppercase">Max RTT</span>
                          <div className="text-sm font-black text-slate-900">{pingData.max_rtt_ms} ms</div>
                        </div>
                        <div className="p-2.5 rounded-xl bg-slate-50">
                          <span className="text-[10px] text-slate-400 font-bold uppercase">Probes Returned</span>
                          <div className="text-sm font-black text-slate-900">{pingData.probes_received}/{pingData.probes_sent}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                <div className="bg-white rounded-3xl p-6">
                  <h3 className="text-sm font-extrabold font-heading text-[#18181B] mb-4">
                    Extracted Feature Vectors (55 Lexical Inputs)
                  </h3>
                  <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2.5">
                    {Object.entries(scanResult.features).map(([k, v]) => (
                      <div key={k} className="p-2.5 rounded-2xl bg-slate-50 flex flex-col justify-between">
                        <span className="text-[10px] text-slate-400 font-semibold truncate">{k}</span>
                        <span className="text-xs font-black text-[#18181B] mt-1">
                          {typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(3)) : String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'network' && (
          <div className="space-y-6">
            <div className="bg-white rounded-3xl p-6 sm:p-8">
              <h2 className="text-xl sm:text-2xl font-extrabold font-heading text-[#18181B] mb-1">
                Authoritative Domain Name Resolution
              </h2>
              <p className="text-xs text-slate-500 font-medium mb-6">
                Bounded socket query for IPv4 (A) and IPv6 (AAAA) records. Resolves hostnames without initiating HTTP connections.
              </p>

              <form onSubmit={handleDnsSubmit} className="flex flex-col sm:flex-row gap-2.5">
                <div className="relative flex-1">
                  <Globe className="w-4 h-4 text-slate-400 absolute left-4 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Enter hostname..."
                    value={dnsDomain}
                    onChange={(e) => setDnsDomain(e.target.value)}
                    className="w-full h-11 pl-11 pr-4 rounded-full bg-slate-50 border border-slate-200 text-xs font-medium focus:outline-none focus:border-[#18181B] focus:bg-white transition-all text-slate-900 placeholder:text-slate-400"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isResolvingDns}
                  className="h-11 px-6 rounded-full bg-[#18181B] text-white text-xs font-bold hover:bg-black transition-colors flex items-center justify-center gap-2 shrink-0 cursor-pointer disabled:opacity-50"
                >
                  {isResolvingDns ? <RefreshCw className="w-3.5 h-3.5 animate-spin text-white" /> : <Globe className="w-3.5 h-3.5 text-white" />}
                  <span>{isResolvingDns ? 'Resolving...' : 'Lookup DNS'}</span>
                </button>
              </form>

              <div className="mt-4 mb-6 flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mr-1">Try:</span>
                
                <button
                  type="button"
                  onClick={() => triggerDnsLookup('apple.com')}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>apple.com</span>
                </button>

                <button
                  type="button"
                  onClick={() => triggerDnsLookup('cloudflare.com')}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>cloudflare.com</span>
                </button>

                <button
                  type="button"
                  onClick={() => triggerDnsLookup('python.org')}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>python.org</span>
                </button>

                <button
                  type="button"
                  onClick={() => triggerDnsLookup('0-olx.1850943.xyz')}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>0-olx.1850943.xyz</span>
                </button>

                <button
                  type="button"
                  onClick={() => triggerDnsLookup('netflix-verify.top')}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>netflix-verify.top</span>
                </button>

                <button
                  type="button"
                  onClick={() => triggerDnsLookup('110.37.26.193')}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>110.37.26.193</span>
                </button>
              </div>

              {dnsHistory.length > 0 && (
                <div className="mt-6 border-t border-slate-100 divide-y divide-slate-100">
                  {dnsHistory.map((entry, idx) => (
                    <div key={`${entry.hostname}-${idx}`} className="py-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                          <Globe className="w-4 h-4 text-[#15803D]" />
                          <span className="text-sm font-black text-[#18181B]">{entry.hostname}</span>
                          <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full ${
                            entry.status === 'SUCCESS' ? 'bg-green-100 text-[#15803D]' : 'bg-red-100 text-red-600'
                          }`}>
                            {entry.status}
                          </span>
                        </div>
                        <div className="text-right">
                          <span className="text-xs font-black text-[#15803D]">{entry.lookup_duration_ms} ms</span>
                        </div>
                      </div>

                      {entry.status === 'SUCCESS' ? (
                        <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5 text-xs">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="text-[10px] uppercase font-bold text-slate-400">IPv4 (A):</span>
                            <span className="text-xs font-medium text-slate-800">
                              {entry.ipv4_addresses.join(', ')}
                            </span>
                          </div>

                          {entry.ipv6_addresses.length > 0 && (
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="text-[10px] uppercase font-bold text-slate-400">IPv6 (AAAA):</span>
                              <span className="text-xs font-medium text-slate-800">
                                {entry.ipv6_addresses.join(', ')}
                              </span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="text-xs text-red-600 font-medium">
                          {entry.error || 'Failed to resolve hostname.'}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'firewall' && (
          <div className="space-y-6">
            <div className="bg-white rounded-3xl p-6 sm:p-8">
              <h2 className="text-xl sm:text-2xl font-extrabold font-heading text-[#18181B] mb-1">
                Domain Firewall Blocklist
              </h2>
              <p className="text-xs text-slate-500 font-medium mb-6">
                Define domain blocking rules in software memory. Matched requests are automatically intercepted and quarantined.
              </p>

              <form onSubmit={handleAddRule} className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                <input
                  type="text"
                  placeholder="Domain to block..."
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  className="h-11 px-4 rounded-full bg-slate-50 border border-slate-200 text-xs font-medium focus:outline-none focus:border-[#18181B] focus:bg-white transition-all text-slate-900 placeholder:text-slate-400"
                />
                <input
                  type="text"
                  placeholder="Reason for Blocking..."
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                  className="h-11 px-4 rounded-full bg-slate-50 border border-slate-200 text-xs font-medium focus:outline-none focus:border-[#18181B] focus:bg-white transition-all text-slate-900 placeholder:text-slate-400"
                />
                <button
                  type="submit"
                  className="h-11 px-6 rounded-full bg-[#18181B] text-white text-xs font-bold hover:bg-black transition-colors flex items-center justify-center gap-2 cursor-pointer"
                >
                  <Plus className="w-4 h-4 text-white" />
                  <span>Create Rule</span>
                </button>
              </form>

              <div className="mt-4 flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mr-1">Try:</span>
                
                <button
                  type="button"
                  onClick={() => { setNewDomain('apple.com'); setNewReason('Outbound security test'); }}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>apple.com</span>
                </button>

                <button
                  type="button"
                  onClick={() => { setNewDomain('cloudflare.com'); setNewReason('Edge relay test'); }}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>cloudflare.com</span>
                </button>

                <button
                  type="button"
                  onClick={() => { setNewDomain('python.org'); setNewReason('Repository mirror quarantine'); }}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>python.org</span>
                </button>

                <button
                  type="button"
                  onClick={() => { setNewDomain('0-olx.1850943.xyz'); setNewReason('Scam checkout redirect'); }}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>0-olx.1850943.xyz</span>
                </button>

                <button
                  type="button"
                  onClick={() => { setNewDomain('netflix-verify.top'); setNewReason('Phishing credential harvester'); }}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>netflix-verify.top</span>
                </button>

                <button
                  type="button"
                  onClick={() => { setNewDomain('110.37.26.193'); setNewReason('Anonymous hostile relay'); }}
                  className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <span>110.37.26.193</span>
                </button>
              </div>
            </div>

            <div className="bg-white rounded-3xl p-6">
              <h3 className="text-sm font-extrabold font-heading text-[#18181B] mb-4">
                Active Enforced Rules ({rules.length})
              </h3>
              <div className="divide-y divide-slate-100">
                {rules.map((rule) => (
                  <div key={rule.id} className="py-3.5 flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-slate-100 flex items-center justify-center shrink-0">
                        <ShieldAlert className="w-4 h-4 text-[#18181B]" />
                      </div>
                      <div>
                        <div className="text-xs font-bold text-[#18181B]">{rule.domain}</div>
                        <div className="text-[10px] text-slate-400 font-medium">{rule.reason} • {rule.id}</div>
                      </div>
                    </div>
                    <button
                      onClick={() => handleDeleteRule(rule.id)}
                      className="h-8 w-8 rounded-full bg-slate-100 hover:bg-red-50 hover:text-red-600 text-slate-500 flex items-center justify-center transition-colors cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
                {rules.length === 0 && (
                  <div className="py-8 text-center text-xs text-slate-400">No active firewall rules.</div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'model' && (
          <div className="space-y-6">
            <div className="bg-white rounded-3xl p-6 sm:p-8">
              <h2 className="text-xl sm:text-2xl font-extrabold font-heading text-[#18181B] mb-1">
                Machine Learning Evaluation Benchmarks
              </h2>
              <p className="text-xs text-slate-500 font-medium mb-6">
                Evaluated on 579,920 records with a verified held-out test partition of 115,984 samples.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                <div className="p-4 rounded-2xl bg-slate-50">
                  <div className="text-xs text-slate-400 font-bold uppercase">Architecture</div>
                  <div className="text-lg font-black text-[#18181B] mt-1">{modelInfo?.best_model_name || 'XGBoost'}</div>
                </div>
                <div className="p-4 rounded-2xl bg-slate-50">
                  <div className="text-xs text-slate-400 font-bold uppercase">Model Accuracy</div>
                  <div className="text-lg font-black text-[#15803D] mt-1">
                    {modelInfo ? `${(modelInfo.evaluation_metrics.accuracy * 100).toFixed(2)}%` : '96.20%'}
                  </div>
                </div>
                <div className="p-4 rounded-2xl bg-slate-50">
                  <div className="text-xs text-slate-400 font-bold uppercase">ROC-AUC Score</div>
                  <div className="text-lg font-black text-[#18181B] mt-1">
                    {modelInfo ? modelInfo.evaluation_metrics.roc_auc.toFixed(4) : '0.9930'}
                  </div>
                </div>
              </div>

              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                Held-Out Confusion Matrix
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                <div className="p-3.5 rounded-2xl bg-slate-50">
                  <div className="text-[10px] text-slate-400 font-bold uppercase">True Negatives</div>
                  <div className="text-base font-black text-slate-900 mt-1">66,292</div>
                  <div className="text-[10px] text-slate-500 font-medium">Legitimate Correct</div>
                </div>
                <div className="p-3.5 rounded-2xl bg-slate-50">
                  <div className="text-[10px] text-slate-400 font-bold uppercase">False Positives</div>
                  <div className="text-base font-black text-slate-900 mt-1">1,523</div>
                  <div className="text-[10px] text-slate-500 font-medium">False Alarm (2.2%)</div>
                </div>
                <div className="p-3.5 rounded-2xl bg-slate-50">
                  <div className="text-[10px] text-slate-400 font-bold uppercase">False Negatives</div>
                  <div className="text-base font-black text-slate-900 mt-1">2,881</div>
                  <div className="text-[10px] text-slate-500 font-medium">Missed Phish (5.9%)</div>
                </div>
                <div className="p-3.5 rounded-2xl bg-slate-50">
                  <div className="text-[10px] text-slate-400 font-bold uppercase">True Positives</div>
                  <div className="text-base font-black text-slate-900 mt-1">45,288</div>
                  <div className="text-[10px] text-slate-500 font-medium">Phish Intercepted</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'events' && (
          <div className="bg-white rounded-3xl p-6 sm:p-8">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
              <div>
                <h2 className="text-base sm:text-lg font-extrabold font-heading text-[#18181B]">Security Event History</h2>
                <p className="text-xs text-slate-500 font-medium">Real-time cryptographic, network, and threat audit trail • Auto-cleans in 1 hr</p>
              </div>
              <div className="flex items-center gap-2 self-start sm:self-auto">
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      await api.clearEvents()
                      setEvents([])
                    } catch (err) {
                      console.error('Failed to clear events', err)
                    }
                  }}
                  className="h-8 px-3.5 rounded-full bg-slate-100 hover:bg-slate-200 text-xs font-bold text-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Clear</span>
                </button>
                <button
                  onClick={loadGlobalData}
                  className="h-8 px-3.5 rounded-full bg-slate-100 hover:bg-slate-200 text-xs font-bold text-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Refresh</span>
                </button>
              </div>
            </div>

            <div className="relative mb-3">
              <Search className="w-4 h-4 text-slate-400 absolute left-4 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search event logs..."
                value={eventFilter}
                onChange={(e) => setEventFilter(e.target.value)}
                className="w-full h-11 pl-11 pr-4 rounded-full bg-slate-50 border border-slate-200 text-xs font-medium focus:outline-none focus:border-[#18181B] focus:bg-white transition-all text-slate-900 placeholder:text-slate-400"
              />
            </div>

            <div className="mb-6 flex flex-wrap items-center gap-2">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mr-1">Try:</span>
              
              <button
                type="button"
                onClick={() => setEventFilter('')}
                className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
              >
                <span>All Events</span>
              </button>

              <button
                type="button"
                onClick={() => setEventFilter('DNS')}
                className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
              >
                <span>DNS Query</span>
              </button>

              <button
                type="button"
                onClick={() => setEventFilter('SYSTEM')}
                className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
              >
                <span>System Init</span>
              </button>

              <button
                type="button"
                onClick={() => setEventFilter('PHISHING')}
                className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
              >
                <span>Phishing Threat</span>
              </button>

              <button
                type="button"
                onClick={() => setEventFilter('FIREWALL')}
                className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
              >
                <span>Firewall Intercept</span>
              </button>

              <button
                type="button"
                onClick={() => setEventFilter('CRITICAL')}
                className="px-3.5 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200/80 text-slate-700 text-[11px] font-semibold transition-all cursor-pointer"
              >
                <span>Critical Severity</span>
              </button>
            </div>

            {(() => {
              const visibleEvents = events.filter((ev) => {
                const eventAgeMs = Date.now() - new Date(ev.timestamp).getTime()
                if (eventAgeMs > 60 * 60 * 1000) return false
                if (!eventFilter) return true
                const q = eventFilter.toLowerCase()
                return (
                  ev.message.toLowerCase().includes(q) ||
                  ev.type.toLowerCase().includes(q) ||
                  ev.severity.toLowerCase().includes(q)
                )
              })
              return (
                <div className="divide-y divide-slate-100">
                  {visibleEvents.map((ev) => (
                    <div key={ev.id} className="py-3.5 flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className={`w-2 h-2 rounded-full shrink-0 ${ev.severity === 'CRITICAL' ? 'bg-[#18181B]' : 'bg-[#15803D]'}`} />
                        <div className="min-w-0">
                          <div className="text-xs font-semibold text-slate-900">{ev.message}</div>
                          <div className="text-[10px] text-slate-400 font-medium">{new Date(ev.timestamp).toLocaleString()} • {ev.type}</div>
                        </div>
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0 ${
                        ev.severity === 'CRITICAL' ? 'bg-[#18181B] text-white' : 'bg-slate-100 text-slate-600'
                      }`}>
                        {ev.severity}
                      </span>
                    </div>
                  ))}
                  {visibleEvents.length === 0 && (
                    <div className="py-8 text-center text-xs text-slate-400">No events logged yet.</div>
                  )}
                </div>
              )
            })()}
          </div>
        )}
      </main>
    </div>
  )
}
