import { EventEmitter } from 'events';

export type SecurityEventType =
  | 'security.alert'
  | 'security_event'
  | 'security_event.created'
  | 'security_event.updated'
  | 'application.created'
  | 'application.updated'
  | 'application.removed'
  | 'application.health_changed'
  | 'organization.created'
  | 'organization.updated'
  | 'organization.deleted'
  | 'organization.removed'
  | 'threat.created'
  | 'threat.updated'
  | 'threat.snapshot'
  | 'log.created'
  | 'incident.created'
  | 'incident.updated'
  | 'incident.deleted'
  | 'incident.snapshot'
  | 'system.health_changed'
  | 'waf.event'
  | 'waf.synced'
  | 'waf.deployment_queued'
  | 'waf.agent_status'
  | 'waf.blocked'
  | 'malware.detected'
  | 'malware.scan_completed'
  | 'malware.action_updated'
  | 'malware.snapshot'
  | 'firewall.event'
  | 'firewall.deployment_queued'
  | 'firewall.agent_status'
  | 'firewall.failed'
  | 'firewall.error'
  | 'network.event'
  | 'network.created'
  | 'network.updated'
  | 'network.deleted'
  | 'authentication.event'
  | 'system.health'
  | 'rule.updated'
  | 'threat_intel.synced'
  | 'threat_intel.ioc_created'
  | 'threat_intel.updated'
  | 'threat_intel.snapshot'
  | 'agent.enrolled'
  | 'agent.heartbeat'
  | 'agent.ingested'
  | 'agent.updated'
  | 'agent.restored'
  | 'agent.removed'
  | 'agent.status'
  | 'agent.offline'
  | 'endpoint.status'
  | 'audit.created'
  | 'contact.created'
  | 'contact.updated'
  | 'report.created'
  | 'report.deleted'
  | 'ai.telemetry'
  | 'ai.analysis.completed'
  | 'analytics.snapshot'
  | 'metric.tick';


export interface BusEventPayload {
  type: SecurityEventType;
  data: any;
  organizationId?: string;
  timestamp: string;
}

class SecurityEventBusEmitter extends EventEmitter {
  constructor() {
    super();
    this.setMaxListeners(100);
  }

  public publish(type: SecurityEventType, data: any, organizationId?: string) {
    const payload: BusEventPayload = {
      type,
      data,
      organizationId,
      timestamp: new Date().toISOString()
    };
    this.emit('event', payload);
    this.emit(type, payload);
  }
}

export const SecurityEventBus = new SecurityEventBusEmitter();
