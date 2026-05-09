import React from 'react';
import { Search, Zap, Terminal, Trash2 } from 'lucide-react';

interface SidebarProps {
  activeTab: 'recon' | 'exploits' | 'raw';
  setActiveTab: (tab: 'recon' | 'exploits' | 'raw') => void;
  eventCount: number;
  criticalHighCount: number;
  lastHeartbeat: string;
  onClearBuffer: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  eventCount,
  criticalHighCount,
  lastHeartbeat,
  onClearBuffer
}) => {
  return (
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
          <strong>{eventCount}</strong>
        </div>
        <div className="stat-item">
          <span>High Risk</span>
          <strong style={{color: 'var(--critical)'}}>{criticalHighCount}</strong>
        </div>
        <div className="stat-item">
          <span>Heartbeat</span>
          <strong style={{fontSize: '0.75rem'}}>{lastHeartbeat}</strong>
        </div>
        <button 
          className="clear-btn"
          onClick={onClearBuffer}
        >
          <Trash2 size={14} style={{ marginRight: '8px' }} /> Clear Buffer
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
