import React, { useState, useEffect, useMemo } from 'react';
import { 
  Shield, 
  Search, 
  Activity, 
  AlertTriangle, 
  Terminal,
  Globe,
  Layers,
  Zap,
  Cpu,
  Database,
  Trash2,
  ChevronRight,
  Server
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
  const [selectedTarget, setSelectedTarget] = useState<string>('All Targets');

  const formatTime = (ts: any) => {
    if (!ts) return 'N/A';
    try {
      const d = new Date(ts);
      return isNaN(d.getTime()) ? 'N/A' : d.toLocaleTimeString([], { hour12: false });
    } catch {
      return 'N/A';
    }
  };

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
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
            payload: data.payload || data,
            job: data.job || {},
            ts: data.ts || data.timestamp || (data.event && data.event.timestamp) || new Date().toISOString()
          };
        } else {
          return;
        }

        setEvents((prev) => [safeData, ...prev].slice(0, 1000));
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

  // Extract unique targets from events
  const allTargets = useMemo(() => {
    const targets = new Set<string>();
    events.forEach(e => {
      const t = e.payload?.target || e.job?.target || e.payload?.event?.target || e.payload?.job_target;
      if (t && typeof t === 'string' && t !== 'unknown') targets.add(t);
    });
    return ['All Targets', ...Array.from(targets).sort()];
  }, [events]);

  const targetEvents = useMemo(() => {
    if (selectedTarget === 'All Targets') return events;
    return events.filter(e => (e.payload?.target || e.job?.target) === selectedTarget);
  }, [events, selectedTarget]);

  const reconEvents = targetEvents.filter(e => typeof e?.event === 'string' && (
    e.event.startsWith('recon.') || 
    e.event.includes('stage') ||
    e.event.includes('subdomain') ||
    e.event.includes('takeover') ||
    e.event.includes('dns') ||
    e.event === 'run_started' ||
    e.event === 'run_completed'
  ));

  const exploitEvents = targetEvents.filter(e => typeof e?.event === 'string' && (
    e.event.startsWith('exploit.') || 
    e.event.startsWith('nuclei.') ||
    e.event === 'finding.new'
  ));

  const globalStats = useMemo(() => {
    const stats = { subdomains: 0, resolved: 0, live: 0, ports: 0, critical: 0, high: 0, medium: 0, low: 0 };
    
    // Group by target to find peak stats per target
    const targetMap = new Map<string, any>();
    
    events.forEach(e => {
      const t = e.payload?.target || e.job?.target || e.payload?.event?.target || e.payload?.job_target || 'unknown';
      const s = e.payload?.stats;
      
      if (s) {
        if (!targetMap.has(t)) {
          targetMap.set(t, { subdomains: 0, resolved: 0, live: 0, ports: 0, critical: 0, high: 0, medium: 0, low: 0 });
        }
        const current = targetMap.get(t);
        current.subdomains = Math.max(current.subdomains, s.subdomains || 0);
        current.resolved = Math.max(current.resolved, s.resolved || 0);
        current.live = Math.max(current.live, s.live_hosts || 0);
        current.ports = Math.max(current.ports, s.ports || 0);
        current.critical = Math.max(current.critical, s.critical_findings || 0);
        current.high = Math.max(current.high, s.high_findings || 0);
        current.medium = Math.max(current.medium, s.medium_findings || 0);
        current.low = Math.max(current.low, s.low_findings || 0);
      }
    });

    if (selectedTarget === 'All Targets') {
      // Sum peaks from ALL targets
      targetMap.forEach(targetStats => {
        stats.subdomains += targetStats.subdomains;
        stats.resolved += targetStats.resolved;
        stats.live += targetStats.live;
        stats.ports += targetStats.ports;
        stats.critical += targetStats.critical;
        stats.high += targetStats.high;
        stats.medium += targetStats.medium;
        stats.low += targetStats.low;
      });
    } else {
      // Only use the selected target's peaks
      const targetStats = targetMap.get(selectedTarget) || stats;
      return targetStats;
    }
    
    return stats;
  }, [events, selectedTarget]);

  const pipelineStages = [
    { id: 'osint', label: 'OSINT' },
    { id: 'subdomains', label: 'ENUM' },
    { id: 'dnsx', label: 'DNS' },
    { id: 'takeover', label: 'TAKEOVER' },
    { id: 'httpx', label: 'PROBE' },
    { id: 'portscan', label: 'PORTS' },
    { id: 'screenshots', label: 'SCREENSHOTS' },
    { id: 'discovery', label: 'SCAN' },
    { id: 'nuclei', label: 'EXPLOIT' },
    { id: 'completed', label: 'DONE' }
  ];

  const currentStageIndex = useMemo(() => {
    let maxIdx = -1;
    const latestStageDone = new Map<number, boolean>();

    // We look through historical events (newest first)
    targetEvents.forEach(e => {
      let stage = (e.payload?.event?.stage || e.payload?.stage || e.event || '').toLowerCase();
      const status = (e.payload?.status || '').toLowerCase();
      const msg = (e.payload?.msg || e.payload?.detail || '').toLowerCase();
      const isDone = status === 'completed' || status === 'done' || msg.includes('done') || msg.includes('completed') || msg.includes('finish');
      
      let currentIdx = -1;
      if (['osint', 'recon'].includes(stage)) currentIdx = 0;
      else if (['subdomains', 'subfinder', 'assetfinder', 'bruteforce', 'dns_bruteforce'].includes(stage)) currentIdx = 1;
      else if (['dnsx', 'dns', 'resolve'].includes(stage)) currentIdx = 2;
      else if (['takeover', 'subzy'].includes(stage)) currentIdx = 3;
      else if (['httpx', 'probe', 'tech'].includes(stage)) currentIdx = 4;
      else if (['portscan', 'naabu'].includes(stage)) currentIdx = 5;
      else if (['screenshots', 'screenshot', 'gowitness'].includes(stage)) currentIdx = 6;
      else if (['discovery', 'dirsearch', 'ffuf', 'urls', 'param_discovery'].includes(stage)) currentIdx = 7;
      else if (['nuclei', 'exploit', 'vuln', 'xss', 'bypass_403', 'graphql', 'secrets', 'github_dork'].includes(stage)) currentIdx = 8;
      else if (['completed', 'pipeline', 'done'].includes(stage)) currentIdx = 9;
      
      if (currentIdx !== -1) {
        if (currentIdx > maxIdx) maxIdx = currentIdx;
        // Since we go newest-first, the first time we see a stage index, it's the latest status
        if (!latestStageDone.has(currentIdx)) {
          latestStageDone.set(currentIdx, isDone);
        }
      }
    });

    // If the latest event for the furthest stage is "DONE", move to next highlight
    if (maxIdx !== -1 && latestStageDone.get(maxIdx) && maxIdx < pipelineStages.length - 1) {
      return maxIdx + 1;
    }

    return maxIdx;
  }, [targetEvents]);

  const filteredEvents = useMemo(() => {
    const pool = activeTab === 'recon' ? reconEvents : activeTab === 'exploits' ? exploitEvents : targetEvents;
    if (!searchTerm) return pool;
    const term = searchTerm.toLowerCase();
    return pool.filter(e => 
      String(e.event).toLowerCase().includes(term) || 
      JSON.stringify(e.payload).toLowerCase().includes(term) ||
      String(e.payload?.target).toLowerCase().includes(term)
    );
  }, [activeTab, targetEvents, reconEvents, exploitEvents, searchTerm]);

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

  return (
    <div className="dashboard">
      <header className="header">
        <div className="logo">
          <Shield className="logo-icon" size={28} />
          <h1>BREACH<span>CONSOLE</span></h1>
        </div>
        
        <div className="header-controls">
          <div className="desktop-only">
            <div className="target-dropdown-container">
              <Globe size={14} className="dropdown-icon" />
              <select 
                className="target-select"
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
              >
                {allTargets.map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="ready-indicator">Core // Armed</div>
          <div className="status">
            <div className={`status-indicator ${connected ? 'online' : 'offline'}`} />
            <span className="status-text">{connected ? 'LINK' : 'OFFLINE'}</span>
          </div>
        </div>
      </header>

      <div className="mobile-only target-bar">
        <div className="target-chips">
          {allTargets.map(t => (
            <button 
              key={t}
              className={`target-chip ${selectedTarget === t ? 'active' : ''}`}
              onClick={() => setSelectedTarget(t)}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      <main className="main">
        <aside className="sidebar">
          <nav>
            <button 
              className={activeTab === 'recon' ? 'active' : ''} 
              onClick={() => setActiveTab('recon')}
            >
              <Search size={18} /> <span>Recon</span>
            </button>
            <button 
              className={activeTab === 'exploits' ? 'active' : ''} 
              onClick={() => setActiveTab('exploits')}
            >
              <Zap size={18} /> <span>Exploits</span>
            </button>
            <button 
              className={activeTab === 'raw' ? 'active' : ''} 
              onClick={() => setActiveTab('raw')}
            >
              <Terminal size={18} /> <span>Logs</span>
            </button>
          </nav>
          
          <div className="stats-box">
            <h3>Telemetry</h3>
            <div className="stat-item">
              <span>Sync Ops</span>
              <strong>{events.length}</strong>
            </div>
            <div className="stat-item">
              <span>Heat Map</span>
              <strong style={{color: 'var(--danger)'}}>{exploitEvents.length}</strong>
            </div>
            <button 
              className="clear-btn"
              onClick={async () => {
                try {
                  await fetch('http://localhost:8080/api/clear', { method: 'POST' });
                  setEvents([]);
                } catch (err) {
                  setEvents([]);
                }
              }}
            >
              <Trash2 size={14} style={{ marginRight: '8px' }} /> Clear Buffer
            </button>
          </div>
        </aside>

        <section className="content">
            {activeTab === 'recon' && (
              <>
                <div className="stats-hero">
                    <div className="hero-stat" onClick={() => setSelectedDetails({title: 'Subdomains', data: targetEvents.find(e => e.payload?.subdomains_preview)?.payload?.subdomains_preview || []})}>
                        <div className="hero-label">Subdomains</div>
                        <div className="hero-value">{globalStats.subdomains}</div>
                    </div>
                    <div className="hero-stat">
                        <div className="hero-label">Resolved</div>
                        <div className="hero-value">{globalStats.resolved}</div>
                    </div>
                    <div className="hero-stat" onClick={() => setSelectedDetails({title: 'Live Hosts', data: targetEvents.find(e => e.payload?.httpx_preview)?.payload?.httpx_preview?.map((h: any) => h.url) || []})}>
                        <div className="hero-label">Live Hosts</div>
                        <div className="hero-value" style={{color: 'var(--success)'}}>{globalStats.live}</div>
                    </div>
                    <div className="hero-stat" onClick={() => setSelectedDetails({title: 'Open Ports', data: targetEvents.find(e => e.payload?.port_preview)?.payload?.port_preview || []})}>
                        <div className="hero-label">Ports</div>
                        <div className="hero-value" style={{color: 'var(--warning)'}}>{globalStats.ports}</div>
                    </div>
                </div>

                {selectedTarget !== 'All Targets' && (
                  <div className="pipeline-stepper">
                    <div className="stepper-line-bg" />
                    <div className="stepper-line-fill" style={{ width: `${Math.max(0, (currentStageIndex / (pipelineStages.length - 1)) * 90)}%` }} />
                    {pipelineStages.map((s, idx) => {
                      const isActive = currentStageIndex === idx;
                      const isCompleted = currentStageIndex > idx;
                      return (
                        <div key={s.id} className={`step ${isActive ? 'active' : ''} ${isCompleted ? 'completed' : ''}`}>
                          <div className="step-dot">
                            {isCompleted ? <Zap size={16} /> : (isActive ? <Cpu size={20} className="active-icon" /> : idx + 1)}
                          </div>
                          <div className="step-label">{s.label}</div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}
            {activeTab === 'exploits' && (
              <div className="stats-hero" style={{ gridTemplateColumns: '1fr' }}>
                  <div className="scorecard">
                    <div className="score-item">
                      <div className="score-val" style={{color: 'var(--critical)'}}>{globalStats.critical}</div>
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
                      <div className="score-val" style={{color: 'var(--low)'}}>{globalStats.low}</div>
                      <div className="score-lbl">Low</div>
                    </div>
                  </div>
              </div>
            )}

            <div className="dashboard-controls">
              <div style={{ position: 'relative' }}>
                <Search size={18} style={{ position: 'absolute', left: '20px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
                <input 
                  type="text" 
                  placeholder={`Search ${activeTab} metadata...`} 
                  className="search-input"
                  style={{ paddingLeft: '54px' }}
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
            </div>

            {filteredEvents.length === 0 ? (
              <div className="empty-state">
                <div style={{ padding: '40px', borderRadius: '50%', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)' }}>
                  <Database size={48} style={{ opacity: 0.3 }} />
                </div>
                <p style={{ fontWeight: 600, letterSpacing: '0.05em' }}>WAITING FOR TELEMETRY...</p>
              </div>
            ) : (
              <div className="event-grid">
                {filteredEvents.map((ev, i) => {
                  const isExploit = ev.event.includes('finding') || ev.payload?.severity;
                  const relevantStats = getRelevantStats(ev);
                  
                  return (
                    <div key={i} className={`event-card ${isExploit ? 'exploit' : ''}`}>
                      <div className="event-header">
                        <div className="event-type">
                          {isExploit ? <Zap size={14} /> : <Activity size={14} />}
                          {(ev.payload?.event?.stage || ev.payload?.stage || ev.event).toUpperCase().replace('_', ' ')}
                        </div>
                        <div className="event-time">{formatTime(ev.ts)}</div>
                      </div>
                      
                      <div className="event-body">
                        {ev.payload?.target && <div className="target-badge"><Globe size={12} style={{marginRight: '6px', verticalAlign: 'middle'}} />{ev.payload.target}</div>}
                        <h3 className="event-title">{ev.payload?.title || ev.event.split('.').pop()?.replace(/_/g, ' ')}</h3>
                        
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
                        
                        {ev.payload?.severity && (
                          <div className={`severity ${ev.payload.severity.toLowerCase()}`}>
                            <AlertTriangle size={14} style={{marginRight: '8px'}} />
                            {ev.payload.severity} // THREAT DETECTED
                          </div>
                        )}

                        <div className="raw-details">
                          <details>
                            <summary><ChevronRight size={14} /> Payload Data</summary>
                            <pre>{JSON.stringify(ev.payload || ev.job, null, 2)}</pre>
                          </details>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {selectedDetails && (
              <div className="modal-overlay" onClick={() => setSelectedDetails(null)}>
                <div className="modal-content" onClick={e => e.stopPropagation()}>
                  <div className="modal-header">
                    <h3>DATA EXPLORER // {selectedDetails.title.toUpperCase()}</h3>
                    <button className="close-modal" onClick={() => setSelectedDetails(null)}>&times;</button>
                  </div>
                  <div className="modal-body">
                    {Array.isArray(selectedDetails.data) ? (
                      <>
                        <div style={{marginBottom: '20px', opacity: 0.6, fontSize: '0.85rem', fontFamily: 'var(--font-mono)'}}>
                          ENTRIES: {selectedDetails.data.length}
                        </div>
                        <div className="preview-items">
                          {selectedDetails.data.slice(0, 100).map((item: any, i: number) => (
                            <span key={i} className="preview-item subdomain">
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
