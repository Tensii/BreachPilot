import React from 'react';
import { Zap, Cpu } from 'lucide-react';

interface PipelineStepperProps {
  currentStageIndex: number;
  stages: { id: string, label: string }[];
}

const PipelineStepper: React.FC<PipelineStepperProps> = ({ 
  currentStageIndex, 
  stages 
}) => {
  return (
    <div className="pipeline-stepper">
      <div className="stepper-line-bg" />
      <div className="stepper-line-fill" style={{ width: `${Math.max(0, (currentStageIndex / (stages.length - 1)) * 90)}%` }} />
      {stages.map((s, idx) => {
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
  );
};

export default PipelineStepper;
