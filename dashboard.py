"""
Continuous ATO Dashboard - FastAPI Backend
Provides REST API for compliance monitoring
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import asyncio
import json
from datetime import datetime
import os

# Import from main application
import sys
sys.path.append('.')
from cato_agent import (
    ContinuousATOAgent, 
    ControlAssessment, 
    ComplianceStatus,
    EvidenceRepository
)

app = FastAPI(
    title="Continuous ATO API",
    description="REST API for AKS Continuous Authority to Operate monitoring",
    version="1.0.0"
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
assessment_running = False
last_assessment_result = None
agent = None

# Configuration
class ClusterConfig(BaseModel):
    subscription_id: str
    resource_group: str
    cluster_name: str

class AssessmentSummary(BaseModel):
    total_controls: int
    implemented: int
    partially_implemented: int
    not_implemented: int
    compliance_percentage: float
    average_risk_score: float
    assessment_date: str

class ControlAssessmentResponse(BaseModel):
    control_id: str
    control_name: str
    family: str
    status: str
    implementation_narrative: str
    evidence_ids: List[str]
    gaps: List[str]
    recommendations: List[str]
    last_assessed: str
    risk_score: int

class AssessmentResults(BaseModel):
    summary: AssessmentSummary
    assessments: List[ControlAssessmentResponse]


# Initialize agent
def initialize_agent(config: ClusterConfig):
    global agent
    agent = ContinuousATOAgent(
        config.subscription_id,
        config.resource_group,
        config.cluster_name
    )
    return agent


@app.post("/api/config")
async def configure_cluster(config: ClusterConfig):
    """Configure AKS cluster for monitoring"""
    try:
        initialize_agent(config)
        return {
            "status": "success",
            "message": "Cluster configured successfully",
            "config": config.dict()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/assess")
async def trigger_assessment(background_tasks: BackgroundTasks):
    """Trigger a new compliance assessment"""
    global assessment_running
    
    if agent is None:
        raise HTTPException(status_code=400, detail="Cluster not configured. Call /api/config first")
    
    if assessment_running:
        raise HTTPException(status_code=409, detail="Assessment already running")
    
    assessment_running = True
    background_tasks.add_task(run_assessment_background)
    
    return {
        "status": "started",
        "message": "Assessment started in background"
    }


async def run_assessment_background():
    """Run assessment in background"""
    global assessment_running, last_assessment_result
    
    try:
        results = await agent.run_assessment()
        
        # Convert to serializable format
        assessments_dict = []
        for a in results['assessments']:
            assessments_dict.append({
                'control_id': a.control_id,
                'control_name': a.control_name,
                'family': a.family,
                'status': a.status.value,
                'implementation_narrative': a.implementation_narrative,
                'evidence_ids': a.evidence_ids,
                'gaps': a.gaps,
                'recommendations': a.recommendations,
                'last_assessed': a.last_assessed.isoformat(),
                'risk_score': a.risk_score
            })
        
        last_assessment_result = {
            'summary': results['summary'],
            'assessments': assessments_dict,
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        last_assessment_result = {
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }
    finally:
        assessment_running = False


@app.get("/api/status")
async def get_status():
    """Get current assessment status"""
    return {
        "assessment_running": assessment_running,
        "agent_configured": agent is not None,
        "last_assessment": last_assessment_result.get('timestamp') if last_assessment_result else None
    }


@app.get("/api/results", response_model=AssessmentResults)
async def get_results():
    """Get latest assessment results"""
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    if 'error' in last_assessment_result:
        raise HTTPException(status_code=500, detail=last_assessment_result['error'])
    
    return last_assessment_result


@app.get("/api/results/summary", response_model=AssessmentSummary)
async def get_summary():
    """Get assessment summary only"""
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    return last_assessment_result['summary']


@app.get("/api/controls")
async def get_all_controls():
    """Get all monitored controls"""
    controls = [
        {
            'id': 'AC-2',
            'name': 'Account Management',
            'family': 'AC',
            'description': 'Manage system accounts including creation, enabling, modification, review, and removal'
        },
        {
            'id': 'AC-3',
            'name': 'Access Enforcement',
            'family': 'AC',
            'description': 'Enforce approved authorizations for logical access'
        },
        {
            'id': 'AC-6',
            'name': 'Least Privilege',
            'family': 'AC',
            'description': 'Employ the principle of least privilege'
        },
        {
            'id': 'SC-7',
            'name': 'Boundary Protection',
            'family': 'SC',
            'description': 'Monitor and control communications at external and internal boundaries'
        },
        {
            'id': 'SC-8',
            'name': 'Transmission Confidentiality and Integrity',
            'family': 'SC',
            'description': 'Protect the confidentiality and integrity of transmitted information'
        },
        {
            'id': 'SC-28',
            'name': 'Protection of Information at Rest',
            'family': 'SC',
            'description': 'Protect the confidentiality and integrity of information at rest'
        }
    ]
    return controls


@app.get("/api/controls/{control_id}")
async def get_control_detail(control_id: str):
    """Get detailed assessment for specific control"""
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    for assessment in last_assessment_result['assessments']:
        if assessment['control_id'] == control_id:
            return assessment
    
    raise HTTPException(status_code=404, detail=f"Control {control_id} not found")


@app.get("/api/evidence")
async def list_evidence():
    """List all stored evidence"""
    try:
        repo = EvidenceRepository()
        evidence_dir = os.path.join(repo.storage_path, 'raw_data')
        
        evidence_files = []
        if os.path.exists(evidence_dir):
            for filename in os.listdir(evidence_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(evidence_dir, filename)
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        evidence_files.append({
                            'filename': filename,
                            'evidence_id': data.get('evidence_id'),
                            'timestamp': data.get('timestamp'),
                            'source': data.get('source')
                        })
        
        return evidence_files
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/evidence/{evidence_id}")
async def get_evidence_detail(evidence_id: str):
    """Get detailed evidence data"""
    try:
        repo = EvidenceRepository()
        filepath = os.path.join(repo.storage_path, 'raw_data', f"{evidence_id}.json")
        
        if not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="Evidence not found")
        
        with open(filepath, 'r') as f:
            return json.load(f)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/gaps")
async def get_all_gaps():
    """Get all identified gaps across controls"""
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    all_gaps = []
    for assessment in last_assessment_result['assessments']:
        for gap in assessment['gaps']:
            all_gaps.append({
                'control_id': assessment['control_id'],
                'control_name': assessment['control_name'],
                'gap': gap,
                'risk_score': assessment['risk_score']
            })
    
    # Sort by risk score descending
    all_gaps.sort(key=lambda x: x['risk_score'], reverse=True)
    return all_gaps


@app.get("/api/recommendations")
async def get_all_recommendations():
    """Get all recommendations across controls"""
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    all_recommendations = []
    for assessment in last_assessment_result['assessments']:
        for rec in assessment['recommendations']:
            all_recommendations.append({
                'control_id': assessment['control_id'],
                'control_name': assessment['control_name'],
                'recommendation': rec,
                'risk_score': assessment['risk_score']
            })
    
    # Sort by risk score descending
    all_recommendations.sort(key=lambda x: x['risk_score'], reverse=True)
    return all_recommendations


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }


@app.get("/")
async def root():
    """Serve frontend dashboard"""
    return FileResponse("static/index.html")


# Mount static files
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)