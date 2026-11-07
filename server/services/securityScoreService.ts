import { db } from '../database/db';
import { collectSystemHealth } from './systemHealthService';
import { getConnectedEndpoints } from './endpointConnectionService';

export interface SecurityScoreResult {
  score: number | null;
  grade: string;
  status: 'OPTIMAL' | 'GOOD' | 'NEEDS_ATTENTION' | 'CRITICAL' | 'INSUFFICIENT DATA';
  statusDisplay: string;
  breakdown: {
    wafCoverage: number;
    firewallCoverage: number;
    threatPosture: number;
    incidentResolution: number;
    engineHealth: number;
    authSecurity: number;
  };
  factors: Array<{
    name: string;
    weight: number;
    score: number;
    status: 'Pass' | 'Warning' | 'Fail';
    details: string;
  }>;
  calculatedAt: string;
}

export function calculateSecurityScore(organizationId = ''): SecurityScoreResult {
  // Check if system has sufficient baseline telemetry
  const totalEvents = db.prepare('SELECT COUNT(*) as count FROM security_events WHERE organization_id = ?').get(organizationId) as { count: number };
  const totalWafRules = db.prepare('SELECT COUNT(*) as count FROM waf_rules WHERE organization_id = ?').get(organizationId) as { count: number };
  const totalFwRules = db.prepare('SELECT COUNT(*) as count FROM firewall_rules WHERE organization_id = ?').get(organizationId) as { count: number };
  const endpoints = getConnectedEndpoints(organizationId);

  // If telemetry data is insufficient (no events, no active endpoint, and no rules defined)
  if (totalEvents.count === 0 && !endpoints.hasConnectedEndpoints && totalWafRules.count === 0 && totalFwRules.count === 0) {
    return {
      score: null,
      grade: 'N/A',
      status: 'INSUFFICIENT DATA',
      statusDisplay: 'DATA TIDAK CUKUP',
      breakdown: {
        wafCoverage: 0,
        firewallCoverage: 0,
        threatPosture: 0,
        incidentResolution: 0,
        engineHealth: 0,
        authSecurity: 0
      },
      factors: [
        {
          name: 'Volume Telemetri / Telemetry Data',
          weight: 0,
          score: 0,
          status: 'Warning',
          details: `DATA TIDAK CUKUP: Basis data memiliki ${totalEvents.count} event telemetri. Membutuhkan minimal 1 endpoint terhubung atau event telemetri untuk menghitung skor valid.`
        }
      ],
      calculatedAt: new Date().toISOString()
    };
  }

  // 1. WAF Engine & Rule Policy Coverage (Weight 20%)
  const activeWafRules = db.prepare('SELECT COUNT(*) as count FROM waf_rules WHERE organization_id = ? AND enabled = 1').get(organizationId) as { count: number };
  const appliedWafAgents = db.prepare("SELECT COUNT(*) as count FROM agent_waf_status WHERE organization_id = ? AND status = 'APPLIED'").get(organizationId) as { count: number };
  const wafScore = totalWafRules.count > 0 
    ? Math.round((activeWafRules.count / totalWafRules.count) * 100) 
    : (appliedWafAgents.count > 0 ? 100 : 0);

  // 2. Firewall Layer 3/4 Policy Enforcement (Weight 20%)
  const activeFwRules = db.prepare('SELECT COUNT(*) as count FROM firewall_rules WHERE organization_id = ? AND enabled = 1').get(organizationId) as { count: number };
  const appliedFwAgents = db.prepare("SELECT COUNT(*) as count FROM agent_firewall_status WHERE organization_id = ? AND status = 'APPLIED'").get(organizationId) as { count: number };
  const fwScore = totalFwRules.count > 0 
    ? Math.round((activeFwRules.count / totalFwRules.count) * 100) 
    : (appliedFwAgents.count > 0 ? 100 : 0);

  // 3. Threat Posture: Jumlah Ancaman Kritis Aktif (Weight 25%)
  const activeThreats = db.prepare(`
    SELECT severity, COUNT(*) as count FROM threats
    WHERE organization_id = ? AND status = 'ACTIVE'
    GROUP BY severity
  `).all(organizationId) as Array<{ severity: string; count: number }>;

  let threatPenalties = 0;
  let criticalThreatsCount = 0;
  for (const t of activeThreats) {
    if (t.severity === 'Critical') {
      threatPenalties += t.count * 20;
      criticalThreatsCount += t.count;
    } else if (t.severity === 'High') {
      threatPenalties += t.count * 10;
    } else if (t.severity === 'Medium') {
      threatPenalties += t.count * 4;
    } else {
      threatPenalties += t.count * 1;
    }
  }
  const threatScore = Math.max(0, 100 - threatPenalties);

  // 4. Insiden yang Belum Terselesaikan (Weight 15%)
  const openIncidents = db.prepare(`
    SELECT COUNT(*) as count FROM incidents
    WHERE organization_id = ? AND status IN ('NEW', 'INVESTIGATING')
  `).get(organizationId) as { count: number };
  const incidentScore = Math.max(0, 100 - (openIncidents.count * 25));

  // 5. Status WAF Engine & Firewall Subsystems (Weight 10%)
  const healthSnapshot = collectSystemHealth();
  const targetServices = ['WAF Engine', 'Next-Gen Firewall', 'API Gateway', 'Endpoint Detection'];
  const monitoredHealth = healthSnapshot.services.filter(s => targetServices.includes(s.service_name));
  const operationalCount = monitoredHealth.filter(h => h.status === 'Operational').length;
  const engineHealthScore = monitoredHealth.length > 0 
    ? Math.round((operationalCount / monitoredHealth.length) * 100) 
    : 100;

  // 6. Kegagalan Autentikasi & MFA Compliance (Weight 10%)
  const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users WHERE organization_id = ?').get(organizationId) as { count: number };
  const mfaUsers = db.prepare('SELECT COUNT(*) as count FROM users WHERE organization_id = ? AND mfa_enabled = 1').get(organizationId) as { count: number };
  const mfaBaseScore = totalUsers.count > 0 ? Math.round((mfaUsers.count / totalUsers.count) * 100) : 100;

  // Query actual authentication failures
  const authFailuresAudit = db.prepare(`
    SELECT COUNT(*) as count FROM audit_logs 
    WHERE organization_id = ? AND action IN ('Login Failed', 'Authentication Failure', 'Failed Login', 'AUTH_FAILED')
  `).get(organizationId) as { count: number };

  const authFailuresEvents = db.prepare(`
    SELECT COUNT(*) as count FROM security_events 
    WHERE organization_id = ? AND (source = 'auth' OR threat_name LIKE '%Auth%' OR threat_name LIKE '%Brute Force%')
  `).get(organizationId) as { count: number };

  const totalAuthFailures = (authFailuresAudit?.count || 0) + (authFailuresEvents?.count || 0);
  const authFailurePenalty = Math.min(50, totalAuthFailures * 10);
  const authSecurityScore = Math.max(0, mfaBaseScore - authFailurePenalty);

  // If system has zero security events at all, honestly return INSUFFICIENT DATA
  if (totalEvents.count === 0) {
    return {
      score: null,
      grade: 'N/A',
      status: 'INSUFFICIENT DATA',
      statusDisplay: 'DATA TIDAK CUKUP',
      breakdown: {
        wafCoverage: wafScore,
        firewallCoverage: fwScore,
        threatPosture: 100,
        incidentResolution: incidentScore,
        engineHealth: engineHealthScore,
        authSecurity: authSecurityScore
      },
      factors: [
        {
          name: 'Telemetri Event Masuk',
          weight: 0,
          score: 0,
          status: 'Warning',
          details: 'DATA TIDAK CUKUP: Belum ada event telemetri yang tercatat di database perimeter.'
        }
      ],
      calculatedAt: new Date().toISOString()
    };
  }

  // Weighted total:
  const weighted = (
    (wafScore * 0.20) +
    (fwScore * 0.20) +
    (threatScore * 0.25) +
    (incidentScore * 0.15) +
    (engineHealthScore * 0.10) +
    (authSecurityScore * 0.10)
  );
  const finalScore = Math.min(100, Math.max(0, Math.round(weighted)));

  let grade = 'A';
  let status: 'OPTIMAL' | 'GOOD' | 'NEEDS_ATTENTION' | 'CRITICAL' = 'OPTIMAL';
  let statusDisplay = 'OPTIMAL';

  if (finalScore >= 90) {
    grade = 'A+';
    status = 'OPTIMAL';
    statusDisplay = 'OPTIMAL';
  } else if (finalScore >= 80) {
    grade = 'A';
    status = 'GOOD';
    statusDisplay = 'BAIK / GOOD';
  } else if (finalScore >= 65) {
    grade = 'B';
    status = 'GOOD';
    statusDisplay = 'CUKUP / FAIR';
  } else if (finalScore >= 50) {
    grade = 'C';
    status = 'NEEDS_ATTENTION';
    statusDisplay = 'PERLU PERHATIAN';
  } else {
    grade = 'F';
    status = 'CRITICAL';
    statusDisplay = 'KRITIS / CRITICAL';
  }

  return {
    score: finalScore,
    grade,
    status,
    statusDisplay,
    breakdown: {
      wafCoverage: wafScore,
      firewallCoverage: fwScore,
      threatPosture: threatScore,
      incidentResolution: incidentScore,
      engineHealth: engineHealthScore,
      authSecurity: authSecurityScore
    },
    factors: [
      {
        name: 'WAF Engine & Policy Coverage',
        weight: 20,
        score: wafScore,
        status: wafScore >= 80 ? 'Pass' : wafScore >= 50 ? 'Warning' : 'Fail',
        details: totalWafRules.count > 0 
          ? `${activeWafRules.count} of ${totalWafRules.count} WAF rules active and enforced.`
          : 'Active WAF mitigation rules inspecting all ingress payloads.'
      },
      {
        name: 'Firewall Policy Enforcement',
        weight: 20,
        score: fwScore,
        status: fwScore >= 80 ? 'Pass' : fwScore >= 50 ? 'Warning' : 'Fail',
        details: totalFwRules.count > 0
          ? `${activeFwRules.count} of ${totalFwRules.count} firewall ACL rules active.`
          : 'Active firewall ACL rules blocking malicious IPs and unauthorised ports.'
      },
      {
        name: 'Active Critical Threats',
        weight: 25,
        score: threatScore,
        status: criticalThreatsCount === 0 ? 'Pass' : criticalThreatsCount <= 1 ? 'Warning' : 'Fail',
        details: criticalThreatsCount > 0 
          ? `${criticalThreatsCount} active critical threat(s) detected (Penalty: -${threatPenalties} points).`
          : 'Zero unmitigated critical threats endangering the web perimeter.'
      },
      {
        name: 'Unresolved Incident Backlog',
        weight: 15,
        score: incidentScore,
        status: openIncidents.count === 0 ? 'Pass' : openIncidents.count <= 2 ? 'Warning' : 'Fail',
        details: `${openIncidents.count} security incident(s) in NEW/INVESTIGATING state.`
      },
      {
        name: 'WAF & Firewall Engine Health',
        weight: 10,
        score: engineHealthScore,
        status: engineHealthScore >= 80 ? 'Pass' : 'Warning',
        details: `${operationalCount} of ${monitoredHealth.length} core defense engines OPERATIONAL.`
      },
      {
        name: 'Authentication Security & Account Access',
        weight: 10,
        score: authSecurityScore,
        status: totalAuthFailures === 0 && mfaBaseScore >= 80 ? 'Pass' : 'Warning',
        details: `${totalAuthFailures} authentication failures; ${mfaUsers.count}/${totalUsers.count} operators MFA enabled.`
      }
    ],
    calculatedAt: new Date().toISOString()
  };
}
