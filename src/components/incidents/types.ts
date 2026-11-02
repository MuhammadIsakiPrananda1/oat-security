import React from 'react';
import { ThreatSeverity, SocTier, Incident, User, EndpointAgent, ProtectedApplication } from '../../types';

export type { ThreatSeverity, SocTier, Incident, User, EndpointAgent, ProtectedApplication };

/**
 * Real Asset Option representing either an enrolled Agent server or a protected web application.
 */
export interface AssetOption {
  id: string;
  name: string;
  type: 'agent' | 'application';
  ip?: string;
  domain?: string;
  status: string;
  os?: string;
  environment?: string;
  hostname?: string;
}

/**
 * SOC Analyst Profile with assigned tier, shifts, and competencies.
 */
export interface SocAnalyst {
  id?: string;
  name: string;
  email: string;
  role: string;
  tier: SocTier;
  shift?: string;
  skills?: string[];
  avatarUrl?: string;
}

/**
 * Top-level workspace section view in the SOC incident console.
 */
export type IncidentSection = 'ALL' | 'L1' | 'L2' | 'L3' | 'GUIDE' | 'AUDIT';

/**
 * Definition for options in the Workspace Dropdown selector.
 */
export interface WorkspaceOption {
  id: IncidentSection;
  label: string;
  group: 'workspaces' | 'governance';
  icon: React.ComponentType<{ className?: string }>;
  iconColor: string;
  badgeText: string;
  badgeStyle: string;
  description: string;
}

/**
 * Consolidated audit trail entry for cross-incident forensic auditing.
 */
export interface IncidentAuditRow {
  incidentId: string;
  title: string;
  severity: ThreatSeverity;
  status: string;
  tier: SocTier;
  time: string;
  declaredAt: string;
  sortMs: number;
  author: string;
  note: string;
}

/**
 * Form draft state for declaring a new incident.
 */
export interface IncidentDraft {
  title: string;
  severity: ThreatSeverity;
  tier: SocTier;
  affectedAsset: string;
  assignedTo: string;
  notes: string;
  immediateContainment?: boolean;
}

/**
 * Metadata profile describing a specific SOC Tier (L1, L2, L3).
 */
export interface TierMetadata {
  name: string;
  badgeLabel: string;
  badgeStyle: string;
  borderStyle: string;
  accentColor: string;
  icon: React.ComponentType<{ className?: string }>;
  targetSla: string;
  roleTitle: string;
  summary: string;
  escalateCondition: string;
}

/**
 * MITRE ATT&CK framework mapping details.
 */
export interface MitreClassification {
  tactic: string;
  technique: string;
  id: string;
}

/**
 * Calculated SLA status for an active incident.
 */
export interface SlaInfo {
  maxMinutes: number;
  elapsedMinutes: number;
  remainingMinutes: number;
  isBreached: boolean;
  isClosed: boolean;
  label: string;
}
