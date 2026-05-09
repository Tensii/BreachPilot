import React from 'react';

interface StatsHeroProps {
  stats: {
    subdomains: number;
    resolved: number;
    live: number;
    ports: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  activeTab: 'recon' | 'exploits' | 'raw';
  onShowDetails: (title: string, data: any) => void;
  targetEvents: any[];
}

const StatsHero: React.FC<StatsHeroProps> = ({ 
  stats, 
  activeTab, 
  onShowDetails,
  targetEvents
}) => {
  if (activeTab === 'recon') {
    return (
      <div className="stats-hero">
        <div className="hero-stat" onClick={() => onShowDetails('Subdomains', targetEvents.find(e => e.payload?.subdomains_preview)?.payload?.subdomains_preview || [])}>
          <div className="hero-label">Subdomains</div>
          <div className="hero-value">{stats.subdomains}</div>
        </div>
        <div className="hero-stat">
          <div className="hero-label">Resolved</div>
          <div className="hero-value">{stats.resolved}</div>
        </div>
        <div className="hero-stat" onClick={() => onShowDetails('Live Hosts', targetEvents.find(e => e.payload?.httpx_preview)?.payload?.httpx_preview?.map((h: any) => h.url) || [])}>
          <div className="hero-label">Live Hosts</div>
          <div className="hero-value" style={{color: 'var(--success)'}}>{stats.live}</div>
        </div>
        <div className="hero-stat" onClick={() => onShowDetails('Open Ports', targetEvents.find(e => e.payload?.port_preview)?.payload?.port_preview || [])}>
          <div className="hero-label">Ports</div>
          <div className="hero-value" style={{color: 'var(--warning)'}}>{stats.ports}</div>
        </div>
      </div>
    );
  }

  if (activeTab === 'exploits') {
    return (
      <div className="stats-hero" style={{ gridTemplateColumns: '1fr' }}>
        <div className="scorecard">
          <div className="score-item">
            <div className="score-val" style={{color: 'var(--critical)'}}>{stats.critical}</div>
            <div className="score-lbl">Critical</div>
          </div>
          <div className="score-item">
            <div className="score-val" style={{color: 'var(--high)'}}>{stats.high}</div>
            <div className="score-lbl">High</div>
          </div>
          <div className="score-item">
            <div className="score-val" style={{color: 'var(--medium)'}}>{stats.medium}</div>
            <div className="score-lbl">Medium</div>
          </div>
          <div className="score-item">
            <div className="score-val" style={{color: 'var(--low)'}}>{stats.low}</div>
            <div className="score-lbl">Low</div>
          </div>
        </div>
      </div>
    );
  }

  return null;
};

export default StatsHero;
