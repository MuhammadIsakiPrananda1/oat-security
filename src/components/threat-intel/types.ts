import { ThreatIntelligenceFeed, ThreatFeedSource, CveMitigationItem } from '../../types';

export type { ThreatIntelligenceFeed, ThreatFeedSource, CveMitigationItem };

export type ThreatIntelTab = 'iocs' | 'lookup' | 'cves';

export interface ThreatLookupData {
  riskScore: number;
  reputation: 'Clean' | 'Suspicious' | 'Malicious' | 'Critical';
  asn?: string;
  isp?: string;
  country?: string;
  countryCode?: string;
  threatCategories: string[];
  providerName: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  associatedThreatActor?: string;
  associatedCves?: string[];
  recommendedAction: 'ALLOW' | 'MONITOR' | 'CHALLENGE' | 'BLOCK';
}

export interface ThreatLookupResponse {
  configured: boolean;
  indicator: string;
  type: string;
  message?: string;
  data?: ThreatLookupData;
}

export interface ThreatIntelStats {
  totalIocs: number;
  blockedIocs: number;
  monitoredIocs: number;
  activeFeeds: number;
  criticalCves: number;
}
