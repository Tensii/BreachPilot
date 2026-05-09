import React from 'react';
import { Shield, Globe } from 'lucide-react';

interface HeaderProps {
  connected: boolean;
  selectedTarget: string;
  allTargets: string[];
  onTargetChange: (target: string) => void;
}

const Header: React.FC<HeaderProps> = ({ 
  connected, 
  selectedTarget, 
  allTargets, 
  onTargetChange 
}) => {
  return (
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
              onChange={(e) => onTargetChange(e.target.value)}
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
  );
};

export default Header;
