import { PredictResponse, NetworkStats, DnsResponse, FirewallRule, SecurityEvent, ModelInfo } from './types'

const BASE_URL = import.meta.env.VITE_API_URL || ''

export const api = {
  async getHealth() {
    const res = await fetch(`${BASE_URL}/api/health`)
    if (!res.ok) throw new Error('Health check failed')
    return res.json()
  },

  async predictUrl(url: string): Promise<PredictResponse> {
    const res = await fetch(`${BASE_URL}/api/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.detail || 'Prediction request failed')
    }
    return res.json()
  },

  async getNetworkStats(): Promise<NetworkStats> {
    const res = await fetch(`${BASE_URL}/api/network/stats`)
    if (!res.ok) throw new Error('Failed to fetch network stats')
    return res.json()
  },

  async resolveDns(domain: string): Promise<DnsResponse> {
    const res = await fetch(`${BASE_URL}/api/network/dns?domain=${encodeURIComponent(domain)}`)
    if (!res.ok) throw new Error('DNS lookup failed')
    return res.json()
  },

  async pingSocket(host: string, port: number = 443, count: number = 3): Promise<import('./types').SocketPingResult> {
    const res = await fetch(`${BASE_URL}/api/network/ping?host=${encodeURIComponent(host)}&port=${port}&count=${count}`)
    if (!res.ok) throw new Error('Socket ping probe failed')
    return res.json()
  },

  async getEvents(limit: number = 50, eventType?: string): Promise<SecurityEvent[]> {
    const query = eventType ? `?limit=${limit}&event_type=${eventType}` : `?limit=${limit}`
    const res = await fetch(`${BASE_URL}/api/events${query}`)
    if (!res.ok) throw new Error('Failed to fetch security events')
    return res.json()
  },

  async clearEvents(): Promise<{ success: boolean; cleared_count: number }> {
    const res = await fetch(`${BASE_URL}/api/events`, {
      method: 'DELETE'
    })
    if (!res.ok) throw new Error('Failed to clear security events')
    return res.json()
  },

  async getFirewallRules(): Promise<FirewallRule[]> {
    const res = await fetch(`${BASE_URL}/api/firewall/rules`)
    if (!res.ok) throw new Error('Failed to fetch firewall rules')
    return res.json()
  },

  async createFirewallRule(domain: string, reason: string): Promise<FirewallRule> {
    const res = await fetch(`${BASE_URL}/api/firewall/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, reason })
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.detail || 'Failed to create firewall rule')
    }
    return res.json()
  },

  async deleteFirewallRule(ruleId: string): Promise<{ success: boolean }> {
    const res = await fetch(`${BASE_URL}/api/firewall/rules/${ruleId}`, {
      method: 'DELETE'
    })
    if (!res.ok) throw new Error('Failed to delete firewall rule')
    return res.json()
  },

  async getModelInfo(): Promise<ModelInfo> {
    const res = await fetch(`${BASE_URL}/api/model/info`)
    if (!res.ok) throw new Error('Failed to fetch model info')
    return res.json()
  }
}
