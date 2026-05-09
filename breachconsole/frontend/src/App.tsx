import React, { useState, useEffect, useMemo } from 'react';
import { Search, Database } from 'lucide-react';
import './App.css';

import Header from './components/Header';
import Sidebar from './components/Sidebar';
import StatsHero from './components/StatsHero';
import PipelineStepper from './components/PipelineStepper';
import EventCard from './components/EventCard';
import Modal from './components/Modal';

interface Event {
  event: string;
  payload?: any;
  job?: any;
  ts: string;
}

const PIPELINE_STAGES = [
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
    // Use the same host as the frontend, but with port 8080
    const wsHost = window.location.hostname;
    const ws = new WebSocket(`${protocol}//${wsHost}:8080/ws/events`);

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const eventName = data.event || data.type || 'unknown';
        const safeData: Event = {
          event: String(eventName),
          payload: data.payload || data,
          job: data.job || {},
          ts: data.ts || data.timestamp || new Date().toISOString()
        };
        setEvents((prev) => [safeData, ...prev].slice(0, 1000));
      } catch (err) {
        console.error('Error processing message:', err);
      }
    };

    return () => ws.close();
  }, []);

  const allTargets = useMemo(() => {
    const targets = new Set<string>();
    events.forEach(e => {
      let t = e.job?.target || e.payload?.job_target || e.payload?.event?.target;
      if (!t && e.payload?.target) {
        const candidate = String(e.payload.target);
        if (!candidate.includes('://') && !candidate.includes('?') && !candidate.includes(' ')) {
          t = candidate;
        }
      }
      if (t && typeof t === 'string' && t !== 'unknown' && t.trim() !== '') {
        targets.add(t);
      }
    });
    return ['All Targets', ...Array.from(targets).sort()];
  }, [events]);

  const activeTargets = useMemo(() => {
    const active = new Set<string>();
    const now = Date.now();
    events.slice(0, 50).forEach(e => {
      const ts = new Date(e.ts).getTime();
      let t = e.job?.target || e.payload?.job_target || e.payload?.event?.target;
      if (t && (now - ts) < 60000) active.add(t);
    });
    return active;
  }, [events]);

  const targetEvents = useMemo(() => {
    if (selectedTarget === 'All Targets') return events;
    return events.filter(e => {
      const t = e.job?.target || e.payload?.job_target || e.payload?.event?.target || e.payload?.target;
      if (!t) return false;
      const sT = String(t);
      if (sT === selectedTarget) return true;
      if (sT.includes('://')) return sT.includes(`://${selectedTarget}`) || sT.includes(`.${selectedTarget}`);
      return false;
    });
  }, [events, selectedTarget]);

  const filteredEvents = useMemo(() => {
    const isReconTab = activeTab === 'recon';
    const isExploitTab = activeTab === 'exploits';
    
    let pool = targetEvents;
    if (isReconTab) {
      pool = targetEvents.filter(e => e.event.startsWith('recon.') || e.event.includes('stage') || e.event.includes('subdomain') || e.event.includes('dns'));
    } else if (isExploitTab) {
      pool = targetEvents.filter(e => e.event.startsWith('exploit.') || e.event.startsWith('nuclei.') || e.event === 'finding.new' || e.payload?.severity);
    }

    if (!searchTerm) return pool;
    const term = searchTerm.toLowerCase();
    return pool.filter(e => 
      String(e.payload?.target || '').toLowerCase().includes(term) || 
      String(e.payload?.title || '').toLowerCase().includes(term) ||
      String(e.event).toLowerCase().includes(term)
    );
  }, [activeTab, targetEvents, searchTerm]);

  const globalStats = useMemo(() => {
    const stats = { subdomains: 0, resolved: 0, live: 0, ports: 0, critical: 0, high: 0, medium: 0, low: 0 };
    const targetMap = new Map<string, any>();
    
    events.forEach(e => {
      let t = e.job?.target || e.payload?.job_target || e.payload?.event?.target || e.payload?.target || 'unknown';
      if (String(t).includes('://')) {
        try { t = new URL(String(t)).hostname; } catch { t = String(t); }
      }
      
      if (!targetMap.has(t)) {
        targetMap.set(t, { subdomains: 0, resolved: 0, live: 0, ports: 0, critical: 0, high: 0, medium: 0, low: 0, _findings: new Set() });
      }
      const current = targetMap.get(t);
      const s = e.payload?.stats;
      if (s) {
        current.subdomains = Math.max(current.subdomains, s.subdomains || 0);
        current.resolved = Math.max(current.resolved, s.resolved || 0);
        current.live = Math.max(current.live, s.live_hosts || 0);
        current.ports = Math.max(current.ports, s.ports || 0);
      }
      
      const sev = e.payload?.severity;
      if (sev) {
        const fingerprint = `${e.event}_${e.payload?.title || ''}_${e.payload?.target || ''}`;
        if (!current._findings.has(fingerprint)) {
          current._findings.add(fingerprint);
          const sUpper = String(sev).toUpperCase();
          if (sUpper === 'CRITICAL') current.critical++;
          else if (sUpper === 'HIGH') current.high++;
          else if (sUpper === 'MEDIUM') current.medium++;
          else if (sUpper === 'LOW') current.low++;
        }
      }
    });

    if (selectedTarget === 'All Targets') {
      targetMap.forEach(ts => {
        Object.keys(stats).forEach(k => (stats as any)[k] += (ts as any)[k]);
      });
    } else {
      return targetMap.get(selectedTarget) || stats;
    }
    return stats;
  }, [events, selectedTarget]);

  const currentStageIndex = useMemo(() => {
    let maxIdx = -1;
    targetEvents.forEach(e => {
      const stage = (e.payload?.stage || e.event || '').toLowerCase();
      let idx = -1;
      if (['osint', 'recon'].includes(stage)) idx = 0;
      else if (['subdomains', 'subfinder'].includes(stage)) idx = 1;
      else if (['dnsx', 'dns'].includes(stage)) idx = 2;
      else if (stage.includes('takeover')) idx = 3;
      else if (['httpx', 'probe'].includes(stage)) idx = 4;
      else if (stage.includes('port')) idx = 5;
      else if (stage.includes('screenshot')) idx = 6;
      else if (['discovery', 'scan'].includes(stage)) idx = 7;
      else if (['nuclei', 'exploit'].includes(stage)) idx = 8;
      else if (stage.includes('done')) idx = 9;
      
      if (idx > maxIdx) maxIdx = idx;
    });
    return maxIdx;
  }, [targetEvents]);

  const handleClearBuffer = async () => {
    try {
      await fetch(`http://${window.location.hostname}:8080/api/clear`, { method: 'POST' });
      setEvents([]);
    } catch (err) {
      setEvents([]);
    }
  };

  return (
    <div className="dashboard">
      <Header 
        connected={connected} 
        selectedTarget={selectedTarget} 
        allTargets={allTargets} 
        onTargetChange={setSelectedTarget} 
      />

      <div className="mobile-only target-bar">
        <div className="target-chips">
          {allTargets.map(t => (
            <button 
              key={t}
              className={`target-chip ${selectedTarget === t ? 'active' : ''} ${t !== 'All Targets' && activeTargets.has(t) ? 'has-heartbeat' : ''}`}
              onClick={() => setSelectedTarget(t)}
            >
              {t !== 'All Targets' && activeTargets.has(t) && <span className="pulse-dot" />}
              {t}
            </button>
          ))}
        </div>
      </div>

      <main className="main">
        <Sidebar 
          activeTab={activeTab} 
          setActiveTab={setActiveTab} 
          eventCount={events.length} 
          criticalHighCount={globalStats.critical + globalStats.high} 
          lastHeartbeat={events.length > 0 ? formatTime(events[0].ts) : '---'}
          onClearBuffer={handleClearBuffer}
        />

        <section className="content">
          <StatsHero 
            stats={globalStats} 
            activeTab={activeTab} 
            onShowDetails={(title, data) => setSelectedDetails({title, data})}
            targetEvents={targetEvents}
          />

          {activeTab === 'recon' && selectedTarget !== 'All Targets' && (
            <PipelineStepper currentStageIndex={currentStageIndex} stages={PIPELINE_STAGES} />
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
              {filteredEvents.map((ev, i) => (
                <EventCard key={i} event={ev} formatTime={formatTime} />
              ))}
            </div>
          )}

          {selectedDetails && (
            <Modal 
              title={selectedDetails.title} 
              data={selectedDetails.data} 
              onClose={() => setSelectedDetails(null)} 
            />
          )}
        </section>
      </main>
    </div>
  );
};

export default App;
