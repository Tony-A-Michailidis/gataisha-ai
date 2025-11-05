"""
Continuous Authority to Operate (cATO) Agent for Azure AKS
Focus: Access Control (AC) and System and Communications Protection (SC)
Standard: NIST 800-53 Rev 5
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import PolicyClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.containerservice import ContainerServiceClient
from kubernetes import client, config
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComplianceStatus(Enum):
    IMPLEMENTED = "Implemented"
    PARTIALLY_IMPLEMENTED = "Partially Implemented"
    NOT_IMPLEMENTED = "Not Implemented"
    NOT_ASSESSED = "Not Assessed"


class ControlFamily(Enum):
    ACCESS_CONTROL = "AC"
    SYSTEM_COMMUNICATIONS_PROTECTION = "SC"


@dataclass
class Evidence:
    """Evidence item for a security control"""
    evidence_id: str
    control_id: str
    timestamp: datetime
    source: str
    description: str
    data: Dict
    
    def to_dict(self):
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result


@dataclass
class ControlAssessment:
    """Assessment result for a NIST control"""
    control_id: str
    control_name: str
    family: str
    status: ComplianceStatus
    implementation_narrative: str
    evidence_ids: List[str]
    gaps: List[str]
    recommendations: List[str]
    last_assessed: datetime
    risk_score: int  # 0-100
    
    def to_dict(self):
        result = asdict(self)
        result['status'] = self.status.value
        result['last_assessed'] = self.last_assessed.isoformat()
        return result


class AzureDataCollector:
    """Collects compliance data from Azure services"""
    
    def __init__(self, subscription_id: str, resource_group: str, cluster_name: str):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.cluster_name = cluster_name
        self.credential = DefaultAzureCredential()
        
    async def collect_policy_compliance(self) -> Dict:
        """Collect Azure Policy compliance state"""
        logger.info("Collecting Azure Policy compliance data...")
        try:
            policy_client = PolicyClient(self.credential, self.subscription_id)
            compliance_states = []
            
            # Get policy states for the resource group
            policy_states = policy_client.policy_states.list_query_results_for_resource_group(
                policy_states_resource="latest",
                subscription_id=self.subscription_id,
                resource_group_name=self.resource_group
            )
            
            for state in policy_states.value:
                compliance_states.append({
                    'policy_definition_id': state.policy_definition_id,
                    'compliance_state': state.compliance_state,
                    'resource_id': state.resource_id,
                    'timestamp': state.timestamp
                })
            
            return {
                'source': 'Azure Policy',
                'compliant_count': len([s for s in compliance_states if s['compliance_state'] == 'Compliant']),
                'non_compliant_count': len([s for s in compliance_states if s['compliance_state'] == 'NonCompliant']),
                'policies': compliance_states
            }
        except Exception as e:
            logger.error(f"Error collecting policy compliance: {e}")
            return {'source': 'Azure Policy', 'error': str(e), 'policies': []}
    
    async def collect_defender_recommendations(self) -> Dict:
        """Collect Microsoft Defender for Cloud recommendations"""
        logger.info("Collecting Defender for Cloud recommendations...")
        try:
            security_client = SecurityCenter(self.credential, self.subscription_id, '')
            recommendations = []
            
            # Get security recommendations
            rec_list = security_client.assessments.list(
                scope=f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}"
            )
            
            for rec in rec_list:
                recommendations.append({
                    'name': rec.name,
                    'display_name': rec.display_name if hasattr(rec, 'display_name') else 'N/A',
                    'status': rec.status.code if hasattr(rec, 'status') else 'Unknown',
                    'severity': rec.metadata.severity if hasattr(rec, 'metadata') else 'Unknown',
                    'description': rec.metadata.description if hasattr(rec, 'metadata') else 'N/A'
                })
            
            return {
                'source': 'Defender for Cloud',
                'total_recommendations': len(recommendations),
                'healthy': len([r for r in recommendations if r['status'] == 'Healthy']),
                'unhealthy': len([r for r in recommendations if r['status'] == 'Unhealthy']),
                'recommendations': recommendations
            }
        except Exception as e:
            logger.error(f"Error collecting Defender recommendations: {e}")
            return {'source': 'Defender for Cloud', 'error': str(e), 'recommendations': []}
    
    async def collect_aks_configuration(self) -> Dict:
        """Collect AKS cluster configuration"""
        logger.info("Collecting AKS configuration...")
        try:
            aks_client = ContainerServiceClient(self.credential, self.subscription_id)
            cluster = aks_client.managed_clusters.get(self.resource_group, self.cluster_name)
            
            return {
                'source': 'AKS API',
                'cluster_name': cluster.name,
                'kubernetes_version': cluster.kubernetes_version,
                'rbac_enabled': cluster.enable_rbac,
                'azure_ad_enabled': cluster.aad_profile is not None,
                'network_policy': cluster.network_profile.network_policy if cluster.network_profile else None,
                'private_cluster': cluster.api_server_access_profile.enable_private_cluster if cluster.api_server_access_profile else False,
                'authorized_ip_ranges': cluster.api_server_access_profile.authorized_ip_ranges if cluster.api_server_access_profile else [],
                'encryption_at_rest': cluster.disk_encryption_set_id is not None
            }
        except Exception as e:
            logger.error(f"Error collecting AKS configuration: {e}")
            return {'source': 'AKS API', 'error': str(e)}


class KubernetesDataCollector:
    """Collects compliance data from Kubernetes API"""
    
    def __init__(self):
        try:
            config.load_kube_config()
        except:
            config.load_incluster_config()
        
        self.v1 = client.CoreV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.networking_v1 = client.NetworkingV1Api()
    
    async def collect_rbac_configuration(self) -> Dict:
        """Collect RBAC configuration"""
        logger.info("Collecting Kubernetes RBAC configuration...")
        try:
            roles = self.rbac_v1.list_role_for_all_namespaces()
            cluster_roles = self.rbac_v1.list_cluster_role()
            role_bindings = self.rbac_v1.list_role_binding_for_all_namespaces()
            cluster_role_bindings = self.rbac_v1.list_cluster_role_binding()
            
            return {
                'source': 'Kubernetes RBAC',
                'roles_count': len(roles.items),
                'cluster_roles_count': len(cluster_roles.items),
                'role_bindings_count': len(role_bindings.items),
                'cluster_role_bindings_count': len(cluster_role_bindings.items),
                'roles': [{'name': r.metadata.name, 'namespace': r.metadata.namespace} for r in roles.items[:10]],
                'cluster_roles': [{'name': r.metadata.name} for r in cluster_roles.items[:10]]
            }
        except Exception as e:
            logger.error(f"Error collecting RBAC configuration: {e}")
            return {'source': 'Kubernetes RBAC', 'error': str(e)}
    
    async def collect_network_policies(self) -> Dict:
        """Collect Network Policies"""
        logger.info("Collecting Network Policies...")
        try:
            network_policies = self.networking_v1.list_network_policy_for_all_namespaces()
            
            policies = []
            for np in network_policies.items:
                policies.append({
                    'name': np.metadata.name,
                    'namespace': np.metadata.namespace,
                    'pod_selector': np.spec.pod_selector.match_labels if np.spec.pod_selector else {},
                    'ingress_rules': len(np.spec.ingress) if np.spec.ingress else 0,
                    'egress_rules': len(np.spec.egress) if np.spec.egress else 0
                })
            
            return {
                'source': 'Network Policies',
                'total_policies': len(policies),
                'policies': policies
            }
        except Exception as e:
            logger.error(f"Error collecting network policies: {e}")
            return {'source': 'Network Policies', 'error': str(e), 'policies': []}
    
    async def collect_pod_security(self) -> Dict:
        """Collect Pod Security information"""
        logger.info("Collecting Pod Security...")
        try:
            pods = self.v1.list_pod_for_all_namespaces()
            
            security_context_issues = []
            for pod in pods.items:
                for container in pod.spec.containers:
                    if container.security_context:
                        if container.security_context.privileged:
                            security_context_issues.append({
                                'pod': pod.metadata.name,
                                'namespace': pod.metadata.namespace,
                                'container': container.name,
                                'issue': 'Running as privileged'
                            })
                        if not container.security_context.run_as_non_root:
                            security_context_issues.append({
                                'pod': pod.metadata.name,
                                'namespace': pod.metadata.namespace,
                                'container': container.name,
                                'issue': 'May run as root'
                            })
            
            return {
                'source': 'Pod Security',
                'total_pods': len(pods.items),
                'security_issues': len(security_context_issues),
                'issues': security_context_issues[:20]  # Limit to 20 for display
            }
        except Exception as e:
            logger.error(f"Error collecting pod security: {e}")
            return {'source': 'Pod Security', 'error': str(e)}


class ControlAssessor:
    """Assesses NIST 800-53 controls based on collected evidence"""
    
    def __init__(self):
        self.controls = self._initialize_controls()
    
    def _initialize_controls(self) -> Dict[str, Dict]:
        """Initialize NIST 800-53 Rev 5 control definitions for AC and SC families"""
        return {
            'AC-1': {
                'name': 'Policy and Procedures',
                'family': 'AC',
                'description': 'Develop, document, and disseminate access control policy and procedures'
            },
            'AC-2': {
                'name': 'Account Management',
                'family': 'AC',
                'description': 'Manage system accounts including creation, enabling, modification, review, and removal'
            },
            'AC-3': {
                'name': 'Access Enforcement',
                'family': 'AC',
                'description': 'Enforce approved authorizations for logical access'
            },
            'AC-6': {
                'name': 'Least Privilege',
                'family': 'AC',
                'description': 'Employ the principle of least privilege'
            },
            'AC-17': {
                'name': 'Remote Access',
                'family': 'AC',
                'description': 'Establish and document usage restrictions for remote access'
            },
            'SC-1': {
                'name': 'Policy and Procedures',
                'family': 'SC',
                'description': 'Develop, document, and disseminate system and communications protection policy'
            },
            'SC-7': {
                'name': 'Boundary Protection',
                'family': 'SC',
                'description': 'Monitor and control communications at external and internal boundaries'
            },
            'SC-8': {
                'name': 'Transmission Confidentiality and Integrity',
                'family': 'SC',
                'description': 'Protect the confidentiality and integrity of transmitted information'
            },
            'SC-12': {
                'name': 'Cryptographic Key Establishment and Management',
                'family': 'SC',
                'description': 'Establish and manage cryptographic keys'
            },
            'SC-13': {
                'name': 'Cryptographic Protection',
                'family': 'SC',
                'description': 'Implement FIPS-validated or NSA-approved cryptography'
            },
            'SC-28': {
                'name': 'Protection of Information at Rest',
                'family': 'SC',
                'description': 'Protect the confidentiality and integrity of information at rest'
            }
        }
    
    def assess_ac_2(self, evidence_data: Dict) -> ControlAssessment:
        """Assess AC-2: Account Management"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0
        
        # Check Azure AD integration
        aks_config = evidence_data.get('aks_configuration', {})
        if not aks_config.get('azure_ad_enabled'):
            gaps.append("Azure AD integration not enabled for AKS cluster")
            recommendations.append("Enable Azure AD integration for centralized identity management")
            risk_score += 30
        
        # Check RBAC
        if not aks_config.get('rbac_enabled'):
            gaps.append("RBAC not enabled on AKS cluster")
            recommendations.append("Enable RBAC to enforce access controls")
            risk_score += 40
        else:
            evidence_ids.append("aks_rbac_enabled")
        
        # Check K8s RBAC configuration
        rbac_config = evidence_data.get('rbac_configuration', {})
        if rbac_config.get('roles_count', 0) == 0 and rbac_config.get('cluster_roles_count', 0) == 0:
            gaps.append("No Roles or ClusterRoles configured")
            recommendations.append("Define proper RBAC roles for account management")
            risk_score += 20
        
        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED
        
        narrative = self._generate_ac2_narrative(aks_config, rbac_config, gaps)
        
        return ControlAssessment(
            control_id='AC-2',
            control_name=self.controls['AC-2']['name'],
            family='AC',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )
    
    def _generate_ac2_narrative(self, aks_config: Dict, rbac_config: Dict, gaps: List[str]) -> str:
        """Generate implementation narrative for AC-2"""
        narrative = f"The AKS cluster implements account management through "
        
        if aks_config.get('azure_ad_enabled'):
            narrative += "Azure AD integration, providing centralized identity management. "
        else:
            narrative += "local Kubernetes accounts. Azure AD integration is not enabled. "
        
        if aks_config.get('rbac_enabled'):
            narrative += f"RBAC is enabled with {rbac_config.get('roles_count', 0)} Roles and " \
                        f"{rbac_config.get('cluster_roles_count', 0)} ClusterRoles configured. "
        else:
            narrative += "RBAC is not enabled, limiting access control capabilities. "
        
        if gaps:
            narrative += f"Identified gaps: {'; '.join(gaps)}."
        
        return narrative
    
    def assess_ac_3(self, evidence_data: Dict) -> ControlAssessment:
        """Assess AC-3: Access Enforcement"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0
        
        aks_config = evidence_data.get('aks_configuration', {})
        rbac_config = evidence_data.get('rbac_configuration', {})
        
        if not aks_config.get('rbac_enabled'):
            gaps.append("RBAC not enabled - cannot enforce access controls")
            recommendations.append("Enable RBAC to enforce access policies")
            risk_score += 50
        else:
            evidence_ids.append("rbac_enforcement")
        
        if rbac_config.get('role_bindings_count', 0) == 0:
            gaps.append("No RoleBindings configured")
            recommendations.append("Create RoleBindings to enforce access controls")
            risk_score += 30
        
        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED
        
        narrative = f"Access enforcement is implemented through Kubernetes RBAC. " \
                   f"RBAC enabled: {aks_config.get('rbac_enabled', False)}. " \
                   f"RoleBindings configured: {rbac_config.get('role_bindings_count', 0)}. " \
                   f"ClusterRoleBindings configured: {rbac_config.get('cluster_role_bindings_count', 0)}."
        
        return ControlAssessment(
            control_id='AC-3',
            control_name=self.controls['AC-3']['name'],
            family='AC',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )
    
    def assess_ac_6(self, evidence_data: Dict) -> ControlAssessment:
        """Assess AC-6: Least Privilege"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0
        
        pod_security = evidence_data.get('pod_security', {})
        security_issues = pod_security.get('security_issues', 0)
        
        if security_issues > 0:
            gaps.append(f"{security_issues} pods with security context issues (privileged/root)")
            recommendations.append("Review and remediate pods running with elevated privileges")
            risk_score += min(security_issues * 2, 40)
        
        rbac_config = evidence_data.get('rbac_configuration', {})
        cluster_role_bindings = rbac_config.get('cluster_role_bindings_count', 0)
        
        if cluster_role_bindings > 10:
            gaps.append(f"High number of ClusterRoleBindings ({cluster_role_bindings}) may indicate over-privileged access")
            recommendations.append("Review ClusterRoleBindings and use namespace-scoped Roles where possible")
            risk_score += 20
        
        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED
        
        narrative = f"Least privilege is enforced through RBAC and pod security contexts. " \
                   f"{pod_security.get('total_pods', 0)} pods analyzed, {security_issues} with privilege issues. " \
                   f"{cluster_role_bindings} ClusterRoleBindings configured."
        
        return ControlAssessment(
            control_id='AC-6',
            control_name=self.controls['AC-6']['name'],
            family='AC',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )
    
    def assess_sc_7(self, evidence_data: Dict) -> ControlAssessment:
        """Assess SC-7: Boundary Protection"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0
        
        aks_config = evidence_data.get('aks_configuration', {})
        network_policies = evidence_data.get('network_policies', {})
        
        # Check network policy implementation
        if not aks_config.get('network_policy'):
            gaps.append("Network policy not enabled on AKS cluster")
            recommendations.append("Enable network policy (Azure CNI or Calico) for network segmentation")
            risk_score += 40
        else:
            evidence_ids.append("network_policy_enabled")
        
        # Check if network policies are defined
        if network_policies.get('total_policies', 0) == 0:
            gaps.append("No NetworkPolicies defined in cluster")
            recommendations.append("Define NetworkPolicies to control pod-to-pod communication")
            risk_score += 30
        
        # Check API server access
        if not aks_config.get('private_cluster'):
            gaps.append("AKS API server is publicly accessible")
            recommendations.append("Consider using private cluster or authorized IP ranges")
            risk_score += 20
        
        if len(aks_config.get('authorized_ip_ranges', [])) == 0 and not aks_config.get('private_cluster'):
            recommendations.append("Configure authorized IP ranges for API server access")
            risk_score += 10
        
        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED
        
        narrative = f"Boundary protection is implemented through network policies and API server access controls. " \
                   f"Network policy: {aks_config.get('network_policy', 'Not configured')}. " \
                   f"{network_policies.get('total_policies', 0)} NetworkPolicies defined. " \
                   f"Private cluster: {aks_config.get('private_cluster', False)}. " \
                   f"Authorized IP ranges: {len(aks_config.get('authorized_ip_ranges', []))}."
        
        return ControlAssessment(
            control_id='SC-7',
            control_name=self.controls['SC-7']['name'],
            family='SC',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )
    
    def assess_sc_8(self, evidence_data: Dict) -> ControlAssessment:
        """Assess SC-8: Transmission Confidentiality and Integrity"""
        gaps = []
        recommendations = []
        evidence_ids = ["tls_default"]
        risk_score = 0
        
        # AKS uses TLS by default for API server communication
        narrative = "Transmission confidentiality and integrity is provided through TLS encryption. " \
                   "AKS API server communication uses TLS by default. " \
                   "Internal pod-to-pod communication should be secured using service mesh or network policies."
        
        network_policies = evidence_data.get('network_policies', {})
        if network_policies.get('total_policies', 0) == 0:
            gaps.append("No NetworkPolicies to enforce encrypted communication")
            recommendations.append("Implement service mesh (Istio, Linkerd) or NetworkPolicies for mTLS")
            risk_score += 30
        
        status = ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else ComplianceStatus.IMPLEMENTED
        
        return ControlAssessment(
            control_id='SC-8',
            control_name=self.controls['SC-8']['name'],
            family='SC',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )
    
    def assess_sc_28(self, evidence_data: Dict) -> ControlAssessment:
        """Assess SC-28: Protection of Information at Rest"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0
        
        aks_config = evidence_data.get('aks_configuration', {})
        
        if aks_config.get('encryption_at_rest'):
            evidence_ids.append("disk_encryption_enabled")
            narrative = "Information at rest is protected through Azure disk encryption. " \
                       "Customer-managed keys are used for encryption."
        else:
            gaps.append("Disk encryption not configured")
            recommendations.append("Enable disk encryption with customer-managed keys")
            risk_score += 40
            narrative = "Information at rest protection is not fully implemented. " \
                       "Disk encryption is not configured with customer-managed keys."
        
        # Check for secrets encryption
        recommendations.append("Verify that Kubernetes secrets are encrypted at rest in etcd")
        risk_score += 10
        
        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED
        
        return ControlAssessment(
            control_id='SC-28',
            control_name=self.controls['SC-28']['name'],
            family='SC',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )


class EvidenceRepository:
    """Stores and manages compliance evidence"""
    
    def __init__(self, storage_path: str = './evidence'):
        self.storage_path = storage_path
        self._ensure_storage()
    
    def _ensure_storage(self):
        """Ensure storage directory exists"""
        import os
        os.makedirs(self.storage_path, exist_ok=True)
        os.makedirs(f"{self.storage_path}/assessments", exist_ok=True)
        os.makedirs(f"{self.storage_path}/raw_data", exist_ok=True)
    
    def store_evidence(self, evidence: Evidence):
        """Store evidence item"""
        import os
        file_path = os.path.join(self.storage_path, 'raw_data', f"{evidence.evidence_id}.json")
        with open(file_path, 'w') as f:
            json.dump(evidence.to_dict(), f, indent=2)
        logger.info(f"Stored evidence: {evidence.evidence_id}")
    
    def store_assessment(self, assessment: ControlAssessment):
        """Store control assessment"""
        import os
        file_path = os.path.join(self.storage_path, 'assessments', f"{assessment.control_id}.json")
        with open(file_path, 'w') as f:
            json.dump(assessment.to_dict(), f, indent=2)
        logger.info(f"Stored assessment: {assessment.control_id}")
    
    def get_all_assessments(self) -> List[ControlAssessment]:
        """Retrieve all assessments"""
        import os
        import glob
        
        assessments = []
        pattern = os.path.join(self.storage_path, 'assessments', '*.json')
        
        for file_path in glob.glob(pattern):
            with open(file_path, 'r') as f:
                data = json.load(f)
                data['status'] = ComplianceStatus(data['status'])
                data['last_assessed'] = datetime.fromisoformat(data['last_assessed'])
                assessments.append(ControlAssessment(**data))
        
        return assessments


class ContinuousATOAgent:
    """Main agent coordinating compliance monitoring"""
    
    def __init__(self, subscription_id: str, resource_group: str, cluster_name: str):
        self.azure_collector = AzureDataCollector(subscription_id, resource_group, cluster_name)
        self.k8s_collector = KubernetesDataCollector()
        self.assessor = ControlAssessor()
        self.repository = EvidenceRepository()
    
    async def collect_all_evidence(self) -> Dict:
        """Collect evidence from all sources"""
        logger.info("Starting evidence collection...")
        
        # Collect from all sources concurrently
        azure_policy, defender_recs, aks_config, rbac_config, network_policies, pod_security = \
            await asyncio.gather(
                self.azure_collector.collect_policy_compliance(),
                self.azure_collector.collect_defender_recommendations(),
                self.azure_collector.collect_aks_configuration(),
                self.k8s_collector.collect_rbac_configuration(),
                self.k8s_collector.collect_network_policies(),
                self.k8s_collector.collect_pod_security()
            )
        
        evidence_data = {
            'azure_policy': azure_policy,
            'defender_recommendations': defender_recs,
            'aks_configuration': aks_config,
            'rbac_configuration': rbac_config,
            'network_policies': network_policies,
            'pod_security': pod_security,
            'collection_timestamp': datetime.now()
        }
        
        # Store raw evidence
        evidence = Evidence(
            evidence_id=f"collection_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            control_id="ALL",
            timestamp=datetime.now(),
            source="Multi-source",
            description="Comprehensive evidence collection",
            data=evidence_data
        )
        self.repository.store_evidence(evidence)
        
        return evidence_data
    
    async def assess_all_controls(self, evidence_data: Dict) -> List[ControlAssessment]:
        """Assess all controls"""
        logger.info("Starting control assessments...")
        
        assessments = [
            self.assessor.assess_ac_2(evidence_data),
            self.assessor.assess_ac_3(evidence_data),
            self.assessor.assess_ac_6(evidence_data),
            self