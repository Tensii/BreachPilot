import React from 'react';
import { Activity, Zap, Globe, AlertTriangle, ChevronRight, Layers, Server } from 'lucide-react';

interface Event {
  event: string;
  payload?: any;
  ts: string;
}

interface EventCardProps {
  event: Event;
  formatTime: (ts: string) => string;
}

const getRelevantStats = (ev: Event) => {
  const stage = (ev.payload?.event?.stage || ev.payload?.stage || ev.event || '').toLowerCase();
  const stats = ev.payload?.stats || {};
  const result: {label: string, value: any, icon: any}[] = [];

  if (stage.includes('subdomain') || stage.includes('osint') || stage.includes('bruteforce')) {
    if (stats.subdomains !== undefined) result.push({label: 'Subdomains', value: stats.subdomains, icon: Layers});
  } else if (stage.includes('dnsx') || stage.includes('takeover')) {
    if (stats.resolved !== undefined) result.push({label: 'Resolved', value: stats.resolved, icon: Zap});
  } else if (stage.includes('httpx') || stage.includes('discovery') || stage.includes('vhost') || stage.includes('screenshot')) {
    if (stats.live_hosts !== undefined) result.push({label: 'Live', value: stats.live_hosts, icon: Activity});
  } else if (stage.includes('portscan')) {
    if (stats.ports !== undefined) result.push({label: 'Ports', value: stats.ports, icon: Server});
  } else {
    if (stats.live_hosts) result.push({label: 'Live', value: stats.live_hosts, icon: Activity});
    if (stats.ports) result.push({label: 'Ports', value: stats.ports, icon: Server});
  }
  
  if (stats.ports > 0 && !result.find(r => r.label === 'Ports')) {
    result.push({label: 'Ports', value: stats.ports, icon: Server});
  }

  return result;
};

const EventCard: React.FC<EventCardProps> = ({ event, formatTime }) => {
  const isExploit = event.event.includes('finding') || event.payload?.severity;
  const relevantStats = getRelevantStats(event);
  
  return (
    <div className={`event-card ${isExploit ? 'exploit' : ''}`}>
      <div className="event-header">
        <div className="event-type">
          {isExploit ? <Zap size={14} /> : <Activity size={14} />}
          {(event.payload?.event?.stage || event.payload?.stage || event.event).toUpperCase().replace('_', ' ')}
        </div>
        <div className="event-time">{formatTime(event.ts)}</div>
      </div>
      
      <div className="event-body">
        {(event.payload?.finding_target || event.payload?.target) && (
          <div className="target-badge">
            <Globe size={12} style={{marginRight: '6px', verticalAlign: 'middle'}} />
            {event.payload.finding_target || event.payload.target}
          </div>
        )}
        <h3 className="event-title">{event.payload?.title || event.event.split('.').pop()?.replace(/_/g, ' ')}</h3>
        
        {relevantStats.length > 0 && (
          <div className="stats-grid">
            {relevantStats.map((s, idx) => (
              <div key={idx} className="mini-stat">
                <span className="label">{s.label}</span>
                <span className="value"><s.icon size={14} style={{marginRight: '6px', opacity: 0.5}} />{s.value}</span>
              </div>
            ))}
          </div>
        )}
        
        {event.payload?.severity && (
          <div className={`severity ${event.payload.severity.toLowerCase()}`}>
            <AlertTriangle size={14} style={{marginRight: '8px'}} />
            {event.payload.severity} // THREAT DETECTED
          </div>
        )}

        <div className="raw-details">
          <details>
            <summary><ChevronRight size={14} /> Payload Data</summary>
            <pre>{JSON.stringify(event.payload, null, 2)}</pre>
          </details>
        </div>
      </div>
    </div>
  );
};

export default EventCard;
