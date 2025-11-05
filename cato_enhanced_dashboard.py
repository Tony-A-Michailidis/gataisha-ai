"""
Enhanced Dashboard API with AI-powered features
Includes executive summaries, remediation plans, and trend analysis
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import asyncio
import json
from datetime import datetime, timedelta
import os
from io import BytesIO

# Import from main application
from cato_agent import (
    ContinuousATOAgent,
    ControlAssessment,
    ComplianceStatus,
    EvidenceRepository
)
from cato_ai_enhanced import (
    AIEnhancedControlAssessor,
    enhance_assessment_with_ai
)

app = FastAPI(
    title="Continuous ATO API - AI Enhanced",
    description="AI-powered REST API for AKS Continuous Authority to Operate monitoring",
    version="2.0.0"
)

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
assessment_history = []  # Store historical assessments
agent = None
ai_assessor = None

# Enhanced Models
class AIFeatureStatus(BaseModel):
    enabled: bool
    model: Optional[str] = None
    features: List[str] = []

class EnhancedAssessmentSummary(BaseModel):
    total_controls: int
    implemented: int
    partially_implemented: int
    not_implemented: int
    compliance_percentage: float
    average_risk_score: float
    assessment_date: str
    ai_enabled: bool
    executive_summary: Optional[Dict] = None

class TrendData(BaseModel):
    dates: List[str]
    compliance_scores: List[float]
    risk_scores: List[float]
    control_trends: Dict[str, List[float]]

class RemediationPlan(BaseModel):
    phases: List[Dict]
    total_estimated_hours: int
    total_duration: str
    resource_requirements: List[str]
    success_criteria: List[str]


def initialize_ai_assessor():
    """Initialize AI assessor if API key is available"""
    global ai_assessor
    api_key = os.getenv('ANTHROPIC_API_KEY')
    ai_assessor = AIEnhancedControlAssessor(api_key)
    return ai_assessor.ai_enabled


# Initialize on startup
@app.on_event("startup")
async def startup_event():
    """Initialize AI features on startup"""
    ai_enabled = initialize_ai_assessor()
    if ai_enabled:
        print("✓ AI features enabled with Claude API")
    else:
        print("⚠ AI features disabled - set ANTHROPIC_API_KEY to enable")


@app.get("/api/ai/status", response_model=AIFeatureStatus)
async def get_ai_status():
    """Get AI feature status"""
    if ai_assessor and ai_assessor.ai_enabled:
        return AIFeatureStatus(
            enabled=True,
            model="claude-sonnet-4-20250514",
            features=[
                "Enhanced Narratives",
                "Intelligent Risk Scoring",
                "Smart Recommendations",
                "Executive Summaries",
                "Remediation Planning"
            ]
        )
    else:
        return AIFeatureStatus(
            enabled=False,
            features=[]
        )


@app.post("/api/assess/enhanced")
async def trigger_enhanced_assessment(background_tasks: BackgroundTasks):
    """Trigger AI-enhanced compliance assessment"""
    global assessment_running
    
    if agent is None:
        raise HTTPException(status_code=400, detail="Cluster not configured")
    
    if assessment_running:
        raise HTTPException(status_code=409, detail="Assessment already running")
    
    assessment_running = True
    background_tasks.add_task(run_enhanced_assessment_background)
    
    return {
        "status": "started",
        "message": "AI-enhanced assessment started",
        "ai_enabled": ai_assessor.ai_enabled if ai_assessor else False
    }


async def run_enhanced_assessment_background():
    """Run enhanced assessment with AI features"""
    global assessment_running, last_assessment_result, assessment_history
    
    try:
        # Run base assessment
        results = await agent.run_assessment()
        
        # Enhance with AI if enabled
        if ai_assessor and ai_assessor.ai_enabled:
            enhanced_assessments = []
            
            # Build related controls status map
            related_controls_status = {
                a.control_id: a.status 
                for a in results['assessments']
            }
            
            # Enhance each assessment
            for assessment in results['assessments']:
                enhanced = await enhance_assessment_with_ai(
                    assessment,
                    results['evidence_data'],
                    ai_assessor,
                    related_controls_status
                )
                enhanced_assessments.append(enhanced)
            
            results['assessments'] = enhanced_assessments
            
            # Generate executive summary
            exec_summary = await ai_assessor.generate_executive_summary(
                enhanced_assessments,
                results['evidence_data']
            )
            results['summary']['executive_summary'] = exec_summary
            results['summary']['ai_enhanced'] = True
            
            # Generate remediation plan
            remediation_plan = await ai_assessor.generate_remediation_plan(
                enhanced_assessments,
                results['evidence_data']
            )
            results['remediation_plan'] = remediation_plan
        else:
            results['summary']['ai_enhanced'] = False
        
        # Convert to serializable format
        assessments_dict = []
        for a in results['assessments']:
            assessment_dict = {
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
            }
            
            # Add AI enhancements if available
            if hasattr(a, 'ai_enhanced'):
                assessment_dict['ai_enhanced'] = a.ai_enhanced
            
            assessments_dict.append(assessment_dict)
        
        last_assessment_result = {
            'summary': results['summary'],
            'assessments': assessments_dict,
            'remediation_plan': results.get('remediation_plan'),
            'timestamp': datetime.now().isoformat()
        }
        
        # Store in history
        assessment_history.append({
            'timestamp': datetime.now().isoformat(),
            'compliance_percentage': results['summary']['compliance_percentage'],
            'average_risk_score': results['summary']['average_risk_score'],
            'assessments': assessments_dict
        })
        
        # Keep only last 30 assessments
        if len(assessment_history) > 30:
            assessment_history = assessment_history[-30:]
        
    except Exception as e:
        last_assessment_result = {
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }
    finally:
        assessment_running = False


@app.get("/api/results/enhanced", response_model=EnhancedAssessmentSummary)
async def get_enhanced_results():
    """Get AI-enhanced assessment results"""
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    if 'error' in last_assessment_result:
        raise HTTPException(status_code=500, detail=last_assessment_result['error'])
    
    return last_assessment_result


@app.get("/api/executive-summary")
async def get_executive_summary():
    """Get executive summary"""
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    summary = last_assessment_result.get('summary', {})
    exec_summary = summary.get('executive_summary')
    
    if not exec_summary:
        raise HTTPException(status_code=404, detail="Executive summary not available. Enable AI features or run enhanced assessment.")
    
    return exec_summary


@app.get("/api/remediation-plan", response_model=RemediationPlan)
async def get_remediation_plan():
    """Get detailed remediation plan"""
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    plan = last_assessment_result.get('remediation_plan')
    
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not available. Enable AI features or run enhanced assessment.")
    
    return plan


@app.get("/api/trends", response_model=TrendData)
async def get_compliance_trends():
    """Get historical compliance trends"""
    if not assessment_history:
        raise HTTPException(status_code=404, detail="No historical data available")
    
    dates = [a['timestamp'][:10] for a in assessment_history]  # Just date part
    compliance_scores = [a['compliance_percentage'] for a in assessment_history]
    risk_scores = [a['average_risk_score'] for a in assessment_history]
    
    # Calculate per-control trends
    control_trends = {}
    all_control_ids = set()
    for assessment in assessment_history:
        for control in assessment['assessments']:
            all_control_ids.add(control['control_id'])
    
    for control_id in all_control_ids:
        control_trends[control_id] = []
        for assessment in assessment_history:
            control_data = next(
                (c for c in assessment['assessments'] if c['control_id'] == control_id),
                None
            )
            if control_data:
                control_trends[control_id].append(control_data['risk_score'])
            else:
                control_trends[control_id].append(None)
    
    return TrendData(
        dates=dates,
        compliance_scores=compliance_scores,
        risk_scores=risk_scores,
        control_trends=control_trends
    )


@app.get("/api/compare")
async def compare_assessments(
    assessment1_timestamp: str,
    assessment2_timestamp: str
):
    """Compare two assessments"""
    
    def find_assessment(timestamp: str):
        for a in assessment_history:
            if a['timestamp'].startswith(timestamp):
                return a
        return None
    
    a1 = find_assessment(assessment1_timestamp)
    a2 = find_assessment(assessment2_timestamp)
    
    if not a1 or not a2:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    # Calculate differences
    comparison = {
        'assessment1': {
            'timestamp': a1['timestamp'],
            'compliance': a1['compliance_percentage'],
            'risk_score': a1['average_risk_score']
        },
        'assessment2': {
            'timestamp': a2['timestamp'],
            'compliance': a2['compliance_percentage'],
            'risk_score': a2['average_risk_score']
        },
        'changes': {
            'compliance_delta': a2['compliance_percentage'] - a1['compliance_percentage'],
            'risk_delta': a2['average_risk_score'] - a1['average_risk_score'],
            'improved_controls': [],
            'degraded_controls': [],
            'new_gaps': [],
            'resolved_gaps': []
        }
    }
    
    # Compare controls
    for c2 in a2['assessments']:
        c1 = next((c for c in a1['assessments'] if c['control_id'] == c2['control_id']), None)
        if c1:
            risk_change = c2['risk_score'] - c1['risk_score']
            if risk_change < -5:  # Improved
                comparison['changes']['improved_controls'].append({
                    'control_id': c2['control_id'],
                    'old_risk': c1['risk_score'],
                    'new_risk': c2['risk_score'],
                    'improvement': abs(risk_change)
                })
            elif risk_change > 5:  # Degraded
                comparison['changes']['degraded_controls'].append({
                    'control_id': c2['control_id'],
                    'old_risk': c1['risk_score'],
                    'new_risk': c2['risk_score'],
                    'degradation': risk_change
                })
            
            # Compare gaps
            c1_gaps = set(c1.get('gaps', []))
            c2_gaps = set(c2.get('gaps', []))
            new_gaps = c2_gaps - c1_gaps
            resolved_gaps = c1_gaps - c2_gaps
            
            if new_gaps:
                comparison['changes']['new_gaps'].extend([
                    {'control': c2['control_id'], 'gap': gap} for gap in new_gaps
                ])
            if resolved_gaps:
                comparison['changes']['resolved_gaps'].extend([
                    {'control': c2['control_id'], 'gap': gap} for gap in resolved_gaps
                ])
    
    return comparison


@app.get("/api/export/ato-package")
async def export_ato_package():
    """Export ATO documentation package"""
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    # Generate comprehensive ATO package
    package = {
        'metadata': {
            'generated_date': datetime.now().isoformat(),
            'cluster_name': 'AKS Cluster',
            'framework': 'NIST 800-53 Rev 5',
            'assessment_type': 'Continuous ATO',
            'ai_enhanced': last_assessment_result.get('summary', {}).get('ai_enhanced', False)
        },
        'executive_summary': last_assessment_result.get('summary', {}).get('executive_summary'),
        'compliance_summary': last_assessment_result.get('summary'),
        'control_assessments': last_assessment_result.get('assessments', []),
        'remediation_plan': last_assessment_result.get('remediation_plan'),
        'evidence_index': []
    }
    
    # List evidence files
    try:
        repo = EvidenceRepository()
        evidence_dir = os.path.join(repo.storage_path, 'raw_data')
        if os.path.exists(evidence_dir):
            for filename in os.listdir(evidence_dir):
                if filename.endswith('.json'):
                    package['evidence_index'].append(filename)
    except Exception:
        pass
    
    # Return as downloadable JSON
    json_str = json.dumps(package, indent=2)
    return StreamingResponse(
        iter([json_str]),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=ato_package_{datetime.now().strftime('%Y%m%d')}.json"
        }
    )


@app.post("/api/ai/analyze-control")
async def ai_analyze_control(control_id: str, custom_question: str):
    """Ask AI a custom question about a specific control"""
    if not ai_assessor or not ai_assessor.ai_enabled:
        raise HTTPException(status_code=503, detail="AI features not enabled")
    
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    # Find control assessment
    control_data = next(
        (c for c in last_assessment_result['assessments'] if c['control_id'] == control_id),
        None
    )
    
    if not control_data:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    
    # Ask Claude
    prompt = f"""You are a NIST 800-53 compliance expert analyzing Azure AKS security controls.

Control Assessment Data:
{json.dumps(control_data, indent=2)}

User Question: {custom_question}

Provide a clear, technically accurate answer based on the assessment data and your expertise."""

    try:
        message = ai_assessor.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )
        
        return {
            "control_id": control_id,
            "question": custom_question,
            "answer": message.content[0].text,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")


@app.get("/api/insights/security-posture")
async def get_security_posture_insights():
    """Get AI-powered security posture insights"""
    if not ai_assessor or not ai_assessor.ai_enabled:
        raise HTTPException(status_code=503, detail="AI features not enabled")
    
    if last_assessment_result is None:
        raise HTTPException(status_code=404, detail="No assessment results available")
    
    # Use AI to analyze overall security posture
    assessments_summary = [
        {
            'control': a['control_id'],
            'status': a['status'],
            'risk': a['risk_score'],
            'gaps_count': len(a['gaps'])
        }
        for a in last_assessment_result['assessments']
    ]
    
    prompt = f"""You are a cloud security architect analyzing the overall security posture of an Azure AKS environment.

Assessment Summary:
{json.dumps(assessments_summary, indent=2)}

Provide insights as JSON:
{{
    "security_score": <0-100>,
    "posture_description": "1-2 sentences",
    "strengths": ["strength1", "strength2", ...],
    "vulnerabilities": ["vuln1", "vuln2", ...],
    "attack_vectors": ["vector1", "vector2", ...],
    "quick_wins": ["win1", "win2", ...],
    "strategic_recommendations": ["rec1", "rec2", ...]
}}"""

    try:
        message = ai_assessor.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )
        
        response_text = message.content[0].text
        start = response_text.find('{')
        end = response_text.rfind('}') + 1
        if start >= 0 and end > start:
            insights = json.loads(response_text[start:end])
            insights['generated_at'] = datetime.now().isoformat()
            return insights
        else:
            raise HTTPException(status_code=500, detail="Failed to parse AI response")
            
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to parse AI insights")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)