import React from 'react';

interface ModalProps {
  title: string;
  data: any;
  onClose: () => void;
}

const Modal: React.FC<ModalProps> = ({ title, data, onClose }) => {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>DATA EXPLORER // {title.toUpperCase()}</h3>
          <button className="close-modal" onClick={onClose}>&times;</button>
        </div>
        <div className="modal-body">
          {Array.isArray(data) ? (
            <>
              <div style={{marginBottom: '20px', opacity: 0.6, fontSize: '0.85rem', fontFamily: 'var(--font-mono)'}}>
                ENTRIES: {data.length}
              </div>
              <div className="preview-items">
                {data.slice(0, 100).map((item: any, i: number) => (
                  <span key={i} className="preview-item subdomain">
                    {typeof item === 'string' ? item : JSON.stringify(item)}
                  </span>
                ))}
              </div>
            </>
          ) : (
            <pre>{JSON.stringify(data, null, 2)}</pre>
          )}
        </div>
      </div>
    </div>
  );
};

export default Modal;
