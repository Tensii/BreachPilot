import React, { useState, useEffect, useMemo } from 'react';
import { 
  Shield, 
  Search, 
  Activity, 
  AlertTriangle, 
  Terminal,
  Globe
} from 'lucide-react';
import './App.css';

interface Event {
  event: string;
  payload?: any;
  job?: any;
  ts: string;
}

const App: React.FC = () => {
  const [events, setEvents] = useState<Event[]>([]);
  const [connected, setConnected] = useState(false);
  const [activeTab, setActiveTab] = useState<'recon' | 'exploits' | 'raw'>('recon');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedDetails, setSelectedDetails] = useState<{title: string, data: any} | null>(null);

  const formatTime = (ts: any) => {
    if (!ts) return 'N/A';
    try {
      const d = new Date(ts);
      return isNaN(d.getTime()) ? 'N/A' : d.toLocaleTimeString();
    } catch {
      return 'N/A';
    }
  };

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // For local dev, we assume backend is on 8000
    const ws = new WebSocket(`${protocol}//${window.location.hostname}:8080/ws/events`);

    ws.onopen = () => {
      setConnected(true);
      console.log('Connected to BreachConsole WebSocket');
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        let safeData: Event;

        if (typeof data === 'string') {
          safeData = {
            event: data,
            payload: {},
            ts: new Date().toISOString()
          };
        } else if (data && typeof data === 'object') {
          // Normalize BreachPilot's different naming conventions
          let eventName = 'unknown';
          if (typeof data.event === 'string') {
            eventName = data.event;
          } else if (data.event && typeof data.event === 'object' && data.event.type) {
            eventName = data.event.type;
          } else if (data.type) {
            eventName = data.type;
          }

          safeData = {
            event: String(eventName),
            payload: data.payload || data, // Fallback to root object if no payload field
            job: data.job || {},
            ts: data.ts || data.timestamp || (data.event && data.event.timestamp) || new Date().toISOString()
          };
        } else {
          return;
        }

        if (safeData.event === 'run_started') {
          setEvents([safeData]);
        } else {
          setEvents((prev) => [safeData, ...prev].slice(0, 500));
        }
      } catch (err) {
        console.error('Error processing message:', err);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      console.log('Disconnected from BreachConsole WebSocket');
    };

    return () => ws.close();
  }, []);

  const reconEvents = events.filter(e => typeof e?.event === 'string' && (
    e.event.startsWith('recon.') || 
    e.event.includes('stage') ||
    e.event.includes('subdomain') ||
    e.event.includes('takeover') ||
    e.event.includes('dns') ||
    e.event === 'run_started' ||
    e.event === 'run_completed'
  ));
  const exploitEvents = events.filter(e => typeof e?.event === 'string' && (
    e.event.startsWith('exploit.') || 
    e.event.startsWith('nuclei.') ||
    e.event === 'finding.new'
  ));

  const globalStats = useMemo(() => {
    const stats = { subdomains: 0, resolved: 0, live: 0, ports: 0, critical: 0, high: 0, medium: 0, low: 0 };
    events.forEach(e => {
      const s = e.payload?.stats;
      if (s) {
        if ((s.subdomains || 0) > stats.subdomains) stats.subdomains = s.subdomains;
        if ((s.resolved || 0) > stats.resolved) stats.resolved = s.resolved;
        if ((s.live_hosts || 0) > stats.live) stats.live = s.live_hosts;
        if ((s.ports || 0) > stats.ports) stats.ports = s.ports;
        
        // Severity mapping
        if (s.critical_findings) stats.critical = Math.max(stats.critical, s.critical_findings);
        if (s.high_findings) stats.high = Math.max(stats.high, s.high_findings);
        if (s.medium_findings) stats.medium = Math.max(stats.medium, s.medium_findings);
        if (s.low_findings) stats.low = Math.max(stats.low, s.low_findings);
      }
    });
    return stats;
  }, [events]);

  const pipelineStages = [
    { id: 'osint', label: 'OSINT' },
    { id: 'subdomains', label: 'Enum' },
    { id: 'dnsx', label: 'DNS' },
    { id: 'httpx', label: 'Probe' },
    { id: 'portscan', label: 'Ports' },
    { id: 'nuclei', label: 'Scan' },
    { id: 'completed', label: 'Done' }
  ];

  const currentStageIndex = useMemo(() => {
    const startIdx = events.findIndex(e => e.event === 'run_started');
    const sessionEvents = startIdx !== -1 ? events.slice(0, startIdx + 1) : events;

    let maxIdx = -1;
    sessionEvents.forEach(e => {
      // Extract stage from various payload formats
      let stage = (e.payload?.event?.stage || e.payload?.stage || '').toLowerCase();
      
      // Fallback: if it's a generic event like "exploit.started", use the event name prefix
      if (!stage && e.event) {
        if (e.event.includes('.')) stage = e.event.split('.')[0];
        else stage = e.event;
      }

      if (!stage || stage === 'startup' || stage === 'job') return;

      let currentIdx = -1;
      if (['osint', 'recon'].includes(stage)) currentIdx = 0;
      else if (['subdomains', 'subfinder', 'assetfinder', 'bruteforce', 'dns_bruteforce'].includes(stage)) currentIdx = 1;
      else if (['dnsx', 'dns', 'resolve', 'takeover', 'nuclei_templates'].includes(stage)) currentIdx = 2;
      else if (['httpx', 'vhost_fuzz', 'probe', 'tech', 'tech_host_mapping', 'discovery', 'urls', 'param_discovery'].includes(stage)) currentIdx = 3;
      else if (['portscan', 'naabu', 'screenshot', 'screenshots'].includes(stage)) currentIdx = 4;
      else if (['nuclei', 'exploit', 'vuln', 'xss', 'bypass_403', 'graphql', 'secrets', 'github_dork', 'nuclei_phase1', 'nuclei_phase2'].includes(stage)) currentIdx = 5;
      else if (['completed', 'pipeline', 'done'].includes(stage)) currentIdx = 6;
      
      if (currentIdx > maxIdx) maxIdx = currentIdx;
    });

    return maxIdx;
  }, [events]);

  const filteredEvents = useMemo(() => {
    const pool = activeTab === 'recon' ? reconEvents : activeTab === 'exploits' ? exploitEvents : events;
    if (!searchTerm) return pool;
    const term = searchTerm.toLowerCase();
    return pool.filter(e => 
      String(e.event).toLowerCase().includes(term) || 
      JSON.stringify(e.payload).toLowerCase().includes(term) ||
      String(e.payload?.target).toLowerCase().includes(term)
    );
  }, [activeTab, events, reconEvents, exploitEvents, searchTerm]);

  const getRelevantStats = (ev: Event) => {
    const stage = (ev.payload?.event?.stage || ev.payload?.stage || ev.event || '').toLowerCase();
    const stats = ev.payload?.stats || {};
    const result: {label: string, value: any}[] = [];

    if (stage.includes('subdomain') || stage.includes('osint') || stage.includes('bruteforce')) {
      if (stats.subdomains !== undefined) result.push({label: 'Subdomains', value: stats.subdomains});
    } else if (stage.includes('dnsx') || stage.includes('takeover')) {
      if (stats.resolved !== undefined) result.push({label: 'Resolved', value: stats.resolved});
    } else if (stage.includes('httpx') || stage.includes('discovery') || stage.includes('vhost') || stage.includes('screenshot')) {
      if (stats.live_hosts !== undefined) result.push({label: 'Live', value: stats.live_hosts});
    } else if (stage.includes('portscan')) {
      if (stats.ports !== undefined) result.push({label: 'Ports', value: stats.ports});
    } else {
      // Default fallback: show Live and Ports if they exist
      if (stats.live_hosts) result.push({label: 'Live', value: stats.live_hosts});
      if (stats.ports) result.push({label: 'Ports', value: stats.ports});
    }
    
    // Always add ports if found and not already added
    if (stats.ports > 0 && !result.find(r => r.label === 'Ports')) {
      result.push({label: 'Ports', value: stats.ports});
    }

    return result;
  };

  return (
    <div className="dashboard">
      <header className="header">
        <div className="logo">
          <Shield className="logo-icon" />
          <h1>BreachConsole</h1>
        </div>
        <div className="ready-indicator">System Ready</div>
        <div className="status">
          <div className={`status-indicator ${connected ? 'online' : 'offline'}`} />
          <span>{connected ? 'LIVE' : 'DISCONNECTED'}</span>
        </div>
      </header>

      <main className="main">
        <aside className="sidebar">
          <nav>
            <button 
              className={activeTab === 'recon' ? 'active' : ''} 
              onClick={() => setActiveTab('recon')}
            >
              <Search size={20} /> Recon
            </button>
            <button 
              className={activeTab === 'exploits' ? 'active' : ''} 
              onClick={() => setActiveTab('exploits')}
            >
              <Activity size={20} /> Exploits
            </button>
            <button 
              className={activeTab === 'raw' ? 'active' : ''} 
              onClick={() => setActiveTab('raw')}
            >
              <Terminal size={20} /> Event Log
            </button>
          </nav>
          
          <div className="stats-box">
            <h3>Quick Stats</h3>
            <div className="stat-item">
              <span>Total Events</span>
              <strong>{events.length}</strong>
            </div>
            <div className="stat-item">
              <span>Findings</span>
              <strong className="text-red">{exploitEvents.length}</strong>
            </div>
            <button 
              className="clear-btn"
              onClick={async () => {
                try {
                  await fetch('http://localhost:8080/api/clear', { method: 'POST' });
                  setEvents([]);
                } catch (err) {
                  console.error("Failed to clear history:", err);
                  setEvents([]); // Fallback to local clear
                }
              }}
            >
              Clear All Data
            </button>
          </div>
        </aside>

        <section className="content">
            {activeTab === 'recon' && (
              <>
                <div className="stats-hero">
                    <div className="stat-item interactive" onClick={() => setSelectedDetails({title: 'Subdomains', data: events.find(e => e.payload?.subdomains_preview)?.payload?.subdomains_preview || []})}>
                        <div className="stat-label">Subdomains</div>
                        <div className="stat-value">{globalStats.subdomains}</div>
                    </div>
                    <div className="stat-item">
                        <div className="stat-label">Resolved</div>
                        <div className="stat-value">{globalStats.resolved}</div>
                    </div>
                    <div className="stat-item interactive" onClick={() => setSelectedDetails({title: 'Live Hosts', data: events.find(e => e.payload?.httpx_preview)?.payload?.httpx_preview?.map((h: any) => h.url) || []})}>
                        <div className="stat-label">Live Hosts</div>
                        <div className="stat-value text-green">{globalStats.live}</div>
                    </div>
                    <div className="stat-item interactive" onClick={() => setSelectedDetails({title: 'Open Ports', data: events.find(e => e.payload?.port_preview)?.payload?.port_preview || []})}>
                        <div className="stat-label">Open Ports</div>
                        <div className="stat-value text-orange">{globalStats.ports}</div>
                    </div>
                </div>

                <div className="pipeline-stepper">
                  <div className="stepper-line-bg" />
                  <div className="stepper-line-fill" style={{ width: `${Math.max(0, currentStageIndex / (pipelineStages.length - 1)) * 100}%` }} />
                  {pipelineStages.map((s, idx) => {
                    const isActive = currentStageIndex === idx;
                    const isCompleted = currentStageIndex > idx;
                    return (
                      <div key={s.id} className={`step ${isActive ? 'active' : ''} ${isCompleted ? 'completed' : ''}`}>
                        <div className="step-dot">{isCompleted ? '✓' : idx + 1}</div>
                        <div className="step-label">{s.label}</div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
            {activeTab === 'exploits' && (
              <div className="stats-hero exploits-hero">
                  <div className="scorecard full-width">
                    <div className="score-item">
                      <div className="score-val text-red">{globalStats.critical}</div>
                      <div className="score-lbl">Critical</div>
                    </div>
                    <div className="score-item">
                      <div className="score-val" style={{color: 'var(--high)'}}>{globalStats.high}</div>
                      <div className="score-lbl">High</div>
                    </div>
                    <div className="score-item">
                      <div className="score-val" style={{color: 'var(--medium)'}}>{globalStats.medium}</div>
                      <div className="score-lbl">Medium</div>
                    </div>
                    <div className="score-item">
                      <div className="score-val text-green">{globalStats.low}</div>
                      <div className="score-lbl">Low</div>
                    </div>
                  </div>
              </div>
            )}

            <div className="dashboard-controls">
              <input 
                type="text" 
                placeholder={`Search ${activeTab} results...`} 
                className="search-input"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>

            {filteredEvents.length === 0 ? (
              <div className="empty-state">
                <Activity size={48} />
                <p>No results match your search or filter.</p>
              </div>
            ) : (
              <div className="event-grid">
                {filteredEvents.map((ev, i) => (
                  <div key={i} className={`event-card animate-in ${ev.event.includes('finding') || ev.payload?.severity ? 'exploit' : ''}`}>
                    <div className="event-header">
                      <div className="event-type">
                        {ev.event.includes('finding') || ev.payload?.severity ? <AlertTriangle size={16} className="text-red" /> : <Globe size={16} />}
                        {(ev.payload?.event?.stage || ev.payload?.stage || ev.event).toUpperCase().replace('_', ' ')}
                      </div>
                      <div className="event-time">{formatTime(ev.ts)}</div>
                    </div>
                    
                    <div className="event-body">
                      {ev.payload?.target && <div className="target-badge">{ev.payload.target}</div>}
                      {ev.payload?.title && <h3 className="event-title">{ev.payload.title}</h3>}
                      {ev.payload?.description && ev.payload.description !== ev.payload.title && <p className="event-description">{ev.payload.description}</p>}
                      
                      {getRelevantStats(ev).length > 0 && (
                        <div className="stats-grid">
                          {getRelevantStats(ev).map((s, idx) => (
                            <div key={idx} className="mini-stat">
                              <span className="label">{s.label}</span>
                              <span className="value">{s.value}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      
                      {ev.payload?.severity && (
                        <div className={`severity ${ev.payload.severity.toLowerCase()}`}>
                          Severity: <span>{ev.payload.severity}</span>
                        </div>
                      )}

                      {ev.payload?.subdomains_preview && ev.payload.subdomains_preview.length > 0 && (
                        <div className="preview-list">
                          <div className="preview-items">
                            {ev.payload.subdomains_preview.slice(0, 8).map((sub: string, idx: number) => (
                              <span key={idx} className="preview-item subdomain">{sub}</span>
                            ))}
                          </div>
                        </div>
                      )}

                      <details className="raw-details">
                        <summary>View Technical Details</summary>
                        <pre>{JSON.stringify(ev.payload || ev.job, null, 2)}</pre>
                      </details>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Modal Explorer */}
            {selectedDetails && (
              <div className="modal-overlay" onClick={() => setSelectedDetails(null)}>
                <div className="modal-content" onClick={e => e.stopPropagation()}>
                  <div className="modal-header">
                    <h3>Explorer: {selectedDetails.title}</h3>
                    <button className="close-modal" onClick={() => setSelectedDetails(null)}>&times;</button>
                  </div>
                  <div className="modal-body">
                    {Array.isArray(selectedDetails.data) ? (
                      <>
                        <div style={{marginBottom: '12px', opacity: 0.6, fontSize: '0.8rem'}}>
                          Showing {Math.min(selectedDetails.data.length, 100)} of {selectedDetails.data.length} items
                        </div>
                        <div className="preview-items" style={{flexWrap: 'wrap', display: 'flex', gap: '8px'}}>
                          {selectedDetails.data.slice(0, 100).map((item: any, i: number) => (
                            <span key={i} className="preview-item subdomain" style={{padding: '8px 12px'}}>
                              {typeof item === 'string' ? item : JSON.stringify(item)}
                            </span>
                          ))}
                        </div>
                      </>
                    ) : (
                      <pre>{JSON.stringify(selectedDetails.data, null, 2)}</pre>
                    )}
                  </div>
                </div>
              </div>
            )}
        </section>
      </main>
    </div>
  );
};

export default App;
