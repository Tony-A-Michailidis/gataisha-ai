"""
AI-Enhanced Control Assessor using Claude API
Provides intelligent narrative generation, risk analysis, and remediation guidance
"""

import os
import json
from typing import Dict, List, Optional
from datetime import datetime
import anthropic
from dataclasses import dataclass

# Import base classes from cato_agent
from cato_agent import (
    ControlAssessment,
    ComplianceStatus,
    Evidence
)


class AIEnhancedControlAssessor:
    """
    Enhanced control assessor using Claude API for:
    - Intelligent narrative generation
    - Context-aware risk analysis
    - Detailed remediation guidance
    - Comparative analysis across time
    - Executive summaries
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if self.api_key:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            self.ai_enabled = True
        else:
            self.ai_enabled = False
            print("Warning: ANTHROPIC_API_KEY not set. AI features disabled.")
        
        self.controls = self._initialize_controls()
    
    def _initialize_controls(self) -> Dict[str, Dict]:
        """Initialize NIST 800-53 Rev 5 control definitions with enhanced metadata"""
        return {
            'AC-2': {
                'name': 'Account Management',
                'family': 'AC',
                'description': 'Manage system accounts including creation, enabling, modification, review, and removal',
                'baseline': ['LOW', 'MODERATE', 'HIGH'],
                'priority': 'P1',
                'related_controls': ['AC-3', 'AC-6', 'IA-2', 'IA-4', 'IA-5', 'IA-8'],
                'nist_guidance': 'Account management includes establishing account types, conditions, and privileges.'
            },
            'AC-3': {
                'name': 'Access Enforcement',
                'family': 'AC',
                'description': 'Enforce approved authorizations for logical access',
                'baseline': ['LOW', 'MODERATE', 'HIGH'],
                'priority': 'P1',
                'related_controls': ['AC-2', 'AC-4', 'AC-6', 'CM-5', 'CM-11'],
                'nist_guidance': 'Access enforcement mechanisms enforce approved authorizations by verifying access rights.'
            },
            'AC-6': {
                'name': 'Least Privilege',
                'family': 'AC',
                'description': 'Employ the principle of least privilege',
                'baseline': ['LOW', 'MODERATE', 'HIGH'],
                'priority': 'P1',
                'related_controls': ['AC-2', 'AC-3', 'AC-5', 'CM-5', 'CM-11'],
                'nist_guidance': 'Least privilege is the principle that users and processes have only the minimum privileges necessary.'
            },
            'AC-17': {
                'name': 'Remote Access',
                'family': 'AC',
                'description': 'Establish and document usage restrictions for remote access',
                'baseline': ['MODERATE', 'HIGH'],
                'priority': 'P1',
                'related_controls': ['AC-2', 'AC-3', 'AC-20', 'IA-2', 'IA-8', 'MA-4'],
                'nist_guidance': 'Remote access includes access to organizational systems by users communicating through external networks.'
            },
            'SC-7': {
                'name': 'Boundary Protection',
                'family': 'SC',
                'description': 'Monitor and control communications at external and internal boundaries',
                'baseline': ['LOW', 'MODERATE', 'HIGH'],
                'priority': 'P1',
                'related_controls': ['AC-4', 'AC-17', 'CA-3', 'CM-7', 'SC-5'],
                'nist_guidance': 'Managed interfaces include gateways, routers, firewalls, guards, network-based malicious code analysis.'
            },
            'SC-8': {
                'name': 'Transmission Confidentiality and Integrity',
                'family': 'SC',
                'description': 'Protect the confidentiality and integrity of transmitted information',
                'baseline': ['MODERATE', 'HIGH'],
                'priority': 'P1',
                'related_controls': ['AC-17', 'PE-4', 'SC-7', 'SC-13', 'SC-20', 'SC-23'],
                'nist_guidance': 'Cryptographic mechanisms can be used to protect information in transmission.'
            },
            'SC-12': {
                'name': 'Cryptographic Key Establishment and Management',
                'family': 'SC',
                'description': 'Establish and manage cryptographic keys',
                'baseline': ['MODERATE', 'HIGH'],
                'priority': 'P1',
                'related_controls': ['SC-13', 'SC-17'],
                'nist_guidance': 'Cryptographic key management includes generation, distribution, storage, and destruction.'
            },
            'SC-13': {
                'name': 'Cryptographic Protection',
                'family': 'SC',
                'description': 'Implement FIPS-validated or NSA-approved cryptography',
                'baseline': ['LOW', 'MODERATE', 'HIGH'],
                'priority': 'P1',
                'related_controls': ['AC-17', 'SC-8', 'SC-12', 'SI-7'],
                'nist_guidance': 'Cryptographic standards include FIPS-validated cryptography and NSA-approved cryptography.'
            },
            'SC-28': {
                'name': 'Protection of Information at Rest',
                'family': 'SC',
                'description': 'Protect the confidentiality and integrity of information at rest',
                'baseline': ['MODERATE', 'HIGH'],
                'priority': 'P1',
                'related_controls': ['AC-3', 'AC-6', 'CA-7', 'CM-3', 'CM-5', 'PE-3', 'SC-8', 'SC-13', 'SI-3', 'SI-7'],
                'nist_guidance': 'Information at rest includes data stored in databases, file systems, and storage devices.'
            }
        }
    
    async def generate_enhanced_narrative(
        self,
        control_id: str,
        evidence_data: Dict,
        gaps: List[str],
        status: ComplianceStatus
    ) -> str:
        """
        Generate intelligent, context-aware implementation narrative using Claude
        """
        if not self.ai_enabled:
            return self._generate_basic_narrative(control_id, evidence_data, gaps)
        
        control_info = self.controls[control_id]
        
        prompt = f"""You are a cybersecurity compliance expert specializing in NIST 800-53 Rev 5 controls for cloud-native Kubernetes environments.

Generate a professional, technically accurate implementation narrative for the following security control assessment:

Control: {control_id} - {control_info['name']}
Description: {control_info['description']}
NIST Guidance: {control_info['nist_guidance']}
Status: {status.value}

Evidence Collected:
{json.dumps(evidence_data, indent=2)}

Identified Gaps:
{json.dumps(gaps, indent=2)}

Please provide:
1. A clear, technical description of how this control IS currently implemented (2-3 sentences)
2. Specific Azure and Kubernetes technologies/features being used
3. Any gaps or weaknesses in the current implementation
4. Overall assessment of the control's effectiveness

Write in a professional tone suitable for an Authority to Operate (ATO) package. Be specific and reference actual configurations found in the evidence. Keep the narrative concise (4-6 sentences total)."""

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            return message.content[0].text
            
        except Exception as e:
            print(f"Error generating AI narrative: {e}")
            return self._generate_basic_narrative(control_id, evidence_data, gaps)
    
    def _generate_basic_narrative(
        self,
        control_id: str,
        evidence_data: Dict,
        gaps: List[str]
    ) -> str:
        """Fallback basic narrative generation"""
        control_info = self.controls[control_id]
        narrative = f"The {control_info['name']} control is implemented through "
        
        if control_id.startswith('AC'):
            aks_config = evidence_data.get('aks_configuration', {})
            rbac_config = evidence_data.get('rbac_configuration', {})
            
            if aks_config.get('rbac_enabled'):
                narrative += f"Kubernetes RBAC with {rbac_config.get('roles_count', 0)} roles. "
            if aks_config.get('azure_ad_enabled'):
                narrative += "Azure AD integration provides centralized identity management. "
        
        elif control_id.startswith('SC'):
            aks_config = evidence_data.get('aks_configuration', {})
            network_policies = evidence_data.get('network_policies', {})
            
            if network_policies.get('total_policies', 0) > 0:
                narrative += f"network segmentation with {network_policies['total_policies']} policies. "
            if aks_config.get('encryption_at_rest'):
                narrative += "Disk encryption is enabled. "
        
        if gaps:
            narrative += f"Identified {len(gaps)} gap(s) requiring remediation."
        
        return narrative
    
    async def generate_intelligent_recommendations(
        self,
        control_id: str,
        gaps: List[str],
        evidence_data: Dict,
        risk_score: int
    ) -> List[str]:
        """
        Generate intelligent, prioritized, actionable recommendations using Claude
        """
        if not self.ai_enabled or not gaps:
            return self._generate_basic_recommendations(control_id, gaps)
        
        control_info = self.controls[control_id]
        
        prompt = f"""You are a cloud security architect specializing in Azure Kubernetes Service (AKS) and NIST 800-53 compliance.

Control: {control_id} - {control_info['name']}
Current Risk Score: {risk_score}/100
Related Controls: {', '.join(control_info['related_controls'])}

Current Environment:
{json.dumps(evidence_data, indent=2)}

Identified Gaps:
{json.dumps(gaps, indent=2)}

Provide 3-5 specific, actionable remediation recommendations. Each recommendation should:
1. Be specific to Azure AKS (not generic advice)
2. Include the Azure/Kubernetes feature or service to use
3. Be prioritized by impact (most important first)
4. Include a concrete action (e.g., "Enable Azure AD integration using: az aks update...")
5. Consider the related controls and holistic security posture

Format as a JSON array of strings, each being one recommendation."""

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1536,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            response_text = message.content[0].text
            # Extract JSON array from response
            start = response_text.find('[')
            end = response_text.rfind(']') + 1
            if start >= 0 and end > start:
                recommendations = json.loads(response_text[start:end])
                return recommendations[:5]  # Limit to 5
            else:
                return self._generate_basic_recommendations(control_id, gaps)
                
        except Exception as e:
            print(f"Error generating AI recommendations: {e}")
            return self._generate_basic_recommendations(control_id, gaps)
    
    def _generate_basic_recommendations(
        self,
        control_id: str,
        gaps: List[str]
    ) -> List[str]:
        """Fallback basic recommendations"""
        recommendations = []
        
        if control_id == 'AC-2' and gaps:
            if any('Azure AD' in gap for gap in gaps):
                recommendations.append("Enable Azure AD integration: az aks update --enable-aad")
            if any('RBAC' in gap for gap in gaps):
                recommendations.append("Enable RBAC: az aks update --enable-rbac")
        
        elif control_id == 'SC-7' and gaps:
            if any('network policy' in gap.lower() for gap in gaps):
                recommendations.append("Enable network policy: az aks create --network-policy azure")
            if any('NetworkPolicies' in gap for gap in gaps):
                recommendations.append("Define NetworkPolicies for pod-to-pod communication")
        
        # Generic recommendation
        if not recommendations:
            recommendations.append(f"Review {control_id} implementation and address identified gaps")
        
        return recommendations
    
    async def calculate_intelligent_risk_score(
        self,
        control_id: str,
        gaps: List[str],
        evidence_data: Dict,
        related_controls_status: Dict[str, ComplianceStatus]
    ) -> Dict:
        """
        Calculate risk score with AI-enhanced context analysis
        Returns: {
            'risk_score': int,
            'risk_level': str,
            'risk_factors': List[str],
            'risk_rationale': str
        }
        """
        if not self.ai_enabled:
            return self._calculate_basic_risk_score(gaps)
        
        control_info = self.controls[control_id]
        
        prompt = f"""You are a cybersecurity risk analyst assessing NIST 800-53 controls for an Azure AKS environment.

Control: {control_id} - {control_info['name']}
Priority: {control_info['priority']}
Baseline: {', '.join(control_info['baseline'])}

Identified Gaps:
{json.dumps(gaps, indent=2)}

Related Controls Status:
{json.dumps({k: v.value for k, v in related_controls_status.items()}, indent=2)}

Current Environment Configuration:
{json.dumps(evidence_data, indent=2)}

Assess the risk on a scale of 0-100 where:
- 0-25: Low risk (minor improvements needed)
- 26-50: Medium risk (should be addressed soon)
- 51-75: High risk (requires prompt attention)
- 76-100: Critical risk (immediate action required)

Consider:
1. Number and severity of gaps
2. Control priority and baseline requirements
3. Status of related controls (cascading risk)
4. Potential impact on confidentiality, integrity, availability
5. Azure/AKS specific security implications

Provide your assessment as JSON:
{{
    "risk_score": <0-100>,
    "risk_level": "<Low|Medium|High|Critical>",
    "risk_factors": ["factor1", "factor2", ...],
    "risk_rationale": "2-3 sentence explanation"
}}"""

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            response_text = message.content[0].text
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(response_text[start:end])
            else:
                return self._calculate_basic_risk_score(gaps)
                
        except Exception as e:
            print(f"Error calculating AI risk score: {e}")
            return self._calculate_basic_risk_score(gaps)
    
    def _calculate_basic_risk_score(self, gaps: List[str]) -> Dict:
        """Fallback basic risk calculation"""
        num_gaps = len(gaps)
        risk_score = min(num_gaps * 20, 100)
        
        if risk_score <= 25:
            risk_level = "Low"
        elif risk_score <= 50:
            risk_level = "Medium"
        elif risk_score <= 75:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': [f"{num_gaps} gaps identified"],
            'risk_rationale': f"Risk score based on {num_gaps} identified gaps."
        }
    
    async def generate_executive_summary(
        self,
        assessments: List[ControlAssessment],
        evidence_data: Dict
    ) -> Dict:
        """
        Generate executive summary with AI-powered insights
        """
        if not self.ai_enabled:
            return self._generate_basic_summary(assessments)
        
        # Prepare summary data
        summary_data = {
            'total_controls': len(assessments),
            'implemented': len([a for a in assessments if a.status == ComplianceStatus.IMPLEMENTED]),
            'partial': len([a for a in assessments if a.status == ComplianceStatus.PARTIALLY_IMPLEMENTED]),
            'not_implemented': len([a for a in assessments if a.status == ComplianceStatus.NOT_IMPLEMENTED]),
            'avg_risk': sum(a.risk_score for a in assessments) / len(assessments) if assessments else 0,
            'top_gaps': [],
            'critical_controls': []
        }
        
        # Get top gaps
        all_gaps = []
        for a in assessments:
            for gap in a.gaps:
                all_gaps.append({
                    'control': a.control_id,
                    'gap': gap,
                    'risk': a.risk_score
                })
        all_gaps.sort(key=lambda x: x['risk'], reverse=True)
        summary_data['top_gaps'] = all_gaps[:5]
        
        # Identify critical controls
        summary_data['critical_controls'] = [
            {'control': a.control_id, 'risk': a.risk_score}
            for a in assessments if a.risk_score > 50
        ]
        
        prompt = f"""You are a Chief Information Security Officer (CISO) preparing an executive summary for leadership regarding the organization's Azure AKS security posture and NIST 800-53 compliance.

Assessment Data:
{json.dumps(summary_data, indent=2)}

Environment Overview:
- AKS Cluster: {evidence_data.get('aks_configuration', {}).get('cluster_name', 'N/A')}
- RBAC Enabled: {evidence_data.get('aks_configuration', {}).get('rbac_enabled', False)}
- Azure AD: {evidence_data.get('aks_configuration', {}).get('azure_ad_enabled', False)}
- Network Policy: {evidence_data.get('aks_configuration', {}).get('network_policy', 'None')}

Provide an executive summary as JSON with:
{{
    "overall_posture": "<Excellent|Good|Fair|Poor>",
    "compliance_readiness": "2-3 sentences on readiness for ATO",
    "key_achievements": ["achievement1", "achievement2", ...],
    "top_concerns": ["concern1", "concern2", "concern3"],
    "recommended_actions": ["action1", "action2", "action3"],
    "estimated_remediation_effort": "<1-2 weeks|2-4 weeks|1-2 months|2-3 months>",
    "executive_recommendation": "1-2 sentences with clear recommendation"
}}

Write in business language suitable for non-technical executives."""

        try:
            message = self.client.messages.create(
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
                exec_summary = json.loads(response_text[start:end])
                exec_summary['metrics'] = summary_data
                return exec_summary
            else:
                return self._generate_basic_summary(assessments)
                
        except Exception as e:
            print(f"Error generating executive summary: {e}")
            return self._generate_basic_summary(assessments)
    
    def _generate_basic_summary(self, assessments: List[ControlAssessment]) -> Dict:
        """Fallback basic summary"""
        total = len(assessments)
        implemented = len([a for a in assessments if a.status == ComplianceStatus.IMPLEMENTED])
        compliance_pct = (implemented / total * 100) if total > 0 else 0
        
        if compliance_pct >= 80:
            posture = "Good"
        elif compliance_pct >= 60:
            posture = "Fair"
        else:
            posture = "Poor"
        
        return {
            'overall_posture': posture,
            'compliance_readiness': f"Current compliance at {compliance_pct:.0f}%. Review gaps and implement recommendations.",
            'key_achievements': [f"{implemented} controls implemented"],
            'top_concerns': ["Review detailed assessment for gaps"],
            'recommended_actions': ["Address high-risk findings"],
            'estimated_remediation_effort': "2-4 weeks",
            'executive_recommendation': "Continue remediation efforts to achieve ATO readiness.",
            'metrics': {
                'total_controls': total,
                'implemented': implemented,
                'compliance_percentage': compliance_pct
            }
        }
    
    async def generate_remediation_plan(
        self,
        assessments: List[ControlAssessment],
        evidence_data: Dict
    ) -> Dict:
        """
        Generate comprehensive, prioritized remediation plan
        """
        if not self.ai_enabled:
            return self._generate_basic_remediation_plan(assessments)
        
        # Group gaps by control
        control_gaps = []
        for a in assessments:
            if a.gaps:
                control_gaps.append({
                    'control_id': a.control_id,
                    'control_name': a.control_name,
                    'risk_score': a.risk_score,
                    'gaps': a.gaps,
                    'recommendations': a.recommendations
                })
        
        control_gaps.sort(key=lambda x: x['risk_score'], reverse=True)
        
        prompt = f"""You are a security architect creating a detailed remediation plan for achieving NIST 800-53 compliance in an Azure AKS environment.

Control Gaps (sorted by risk):
{json.dumps(control_gaps, indent=2)}

Environment:
{json.dumps(evidence_data.get('aks_configuration', {}), indent=2)}

Create a comprehensive remediation plan as JSON:
{{
    "phases": [
        {{
            "phase_number": 1,
            "phase_name": "Critical Security Controls",
            "duration": "1-2 weeks",
            "tasks": [
                {{
                    "task_id": "T1",
                    "control": "AC-2",
                    "priority": "Critical",
                    "description": "specific action",
                    "commands": ["az aks command..."],
                    "effort_hours": 4,
                    "dependencies": []
                }}
            ]
        }}
    ],
    "total_estimated_hours": 40,
    "total_duration": "4-6 weeks",
    "resource_requirements": ["Azure admin", "Kubernetes admin", ...],
    "success_criteria": ["criterion1", ...]
}}

Organize into logical phases (Critical → High → Medium → Low risk).
Provide specific Azure CLI or kubectl commands where applicable.
Consider dependencies between tasks."""

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            response_text = message.content[0].text
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(response_text[start:end])
            else:
                return self._generate_basic_remediation_plan(assessments)
                
        except Exception as e:
            print(f"Error generating remediation plan: {e}")
            return self._generate_basic_remediation_plan(assessments)
    
    def _generate_basic_remediation_plan(self, assessments: List[ControlAssessment]) -> Dict:
        """Fallback basic remediation plan"""
        high_risk = [a for a in assessments if a.risk_score > 50]
        medium_risk = [a for a in assessments if 25 < a.risk_score <= 50]
        
        tasks = []
        task_id = 1
        
        for a in high_risk:
            for rec in a.recommendations[:2]:
                tasks.append({
                    'task_id': f'T{task_id}',
                    'control': a.control_id,
                    'priority': 'High',
                    'description': rec,
                    'effort_hours': 4
                })
                task_id += 1
        
        return {
            'phases': [{
                'phase_number': 1,
                'phase_name': 'High Risk Remediation',
                'duration': '2-4 weeks',
                'tasks': tasks
            }],
            'total_estimated_hours': len(tasks) * 4,
            'total_duration': '2-4 weeks',
            'resource_requirements': ['Security Engineer', 'AKS Administrator'],
            'success_criteria': ['Address all high-risk findings']
        }


# Integration with main agent
async def enhance_assessment_with_ai(
    assessment: ControlAssessment,
    evidence_data: Dict,
    ai_assessor: AIEnhancedControlAssessor,
    related_controls_status: Dict[str, ComplianceStatus]
) -> ControlAssessment:
    """Enhance an existing assessment with AI-generated content"""
    
    # Generate enhanced narrative
    narrative = await ai_assessor.generate_enhanced_narrative(
        assessment.control_id,
        evidence_data,
        assessment.gaps,
        assessment.status
    )
    
    # Generate intelligent recommendations
    recommendations = await ai_assessor.generate_intelligent_recommendations(
        assessment.control_id,
        assessment.gaps,
        evidence_data,
        assessment.risk_score
    )
    
    # Calculate intelligent risk score
    risk_analysis = await ai_assessor.calculate_intelligent_risk_score(
        assessment.control_id,
        assessment.gaps,
        evidence_data,
        related_controls_status
    )
    
    # Update assessment
    assessment.implementation_narrative = narrative
    assessment.recommendations = recommendations
    assessment.risk_score = risk_analysis['risk_score']
    
    # Add enhanced metadata
    if not hasattr(assessment, 'ai_enhanced'):
        assessment.ai_enhanced = {
            'risk_level': risk_analysis['risk_level'],
            'risk_factors': risk_analysis['risk_factors'],
            'risk_rationale': risk_analysis['risk_rationale']
        }
    
    return assessment