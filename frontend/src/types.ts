export interface PredictResponse {
  url: string;
  normalized_url: string;
  verdict: 'phishing' | 'legitimate';
  is_phishing: boolean;
  risk_score: number;
  confidence: number;
  features: Record<string, number>;
  indicators: string[];
  inference_time_ms: number;
  model_version: string;
  is_firewall_blocked: boolean;
  firewall_rule?: {
    id: string;
    domain: string;
    reason: string;
    action: string;
  };
  network_telemetry?: {
    hostname: string;
    scheme: string;
    port: number;
    dns_status: string;
    dns_ms: number;
    resolved_ips: string[];
    target_ip?: string;
    tcp_status: string;
    tcp_handshake_ms: number;
    tls?: {
      version: string;
      cipher_suite: string;
      tls_handshake_ms: number;
      issuer_org: string;
      valid_to: string;
      status: string;
      error?: string;
    };
    error?: string;
  };
  safety_report?: {
    icon: string;
    headline: string;
    summary: string;
    observations: string[];
    recommendation: string;
    domain_age?: string;
    root_domain?: string;
  };
}

export interface SocketPingResult {
  hostname: string;
  port: number;
  probes_sent: number;
  probes_received: number;
  rtt_samples_ms: number[];
  avg_rtt_ms: number;
  min_rtt_ms: number;
  max_rtt_ms: number;
  jitter_ms: number;
  packet_loss_pct: number;
}

export interface NetworkStats {
  total_requests: number;
  predictions_count: number;
  dns_lookups_count: number;
  blocked_requests_count: number;
  error_count: number;
  avg_latency_ms: number;
  median_latency_ms: number;
  active_firewall_rules: number;
  total_logged_events: number;
}

export interface DnsResponse {
  hostname: string;
  status: 'SUCCESS' | 'FAILED' | 'TIMEOUT';
  ipv4_addresses: string[];
  ipv6_addresses: string[];
  lookup_duration_ms: number;
  error?: string;
  timestamp: string;
}

export interface FirewallRule {
  id: string;
  domain: string;
  reason: string;
  action: string;
  created_at: string;
  hits_count: number;
  enforced: boolean;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  message: string;
  details: Record<string, any>;
}

export interface ModelInfo {
  best_model_name: string;
  evaluation_metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    roc_auc: number;
    confusion_matrix: {
      true_negative: number;
      false_positive: number;
      false_negative: number;
      true_positive: number;
    };
  };
  candidate_comparisons: Array<{
    Model: string;
    Accuracy: number;
    Precision: number;
    Recall: number;
    F1: number;
    ROC_AUC: number;
    Fit_Time_s: number;
    Latency_ms: number;
  }>;
  dataset_statistics: {
    source: string;
    total_records: number;
    train_records: number;
    test_records: number;
    class_counts: Record<string, number>;
  };
  metadata: {
    feature_count: number;
    approach: string;
    timestamp: string;
  };
}
