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
    AUDIT_ACCOUNTABILITY = "AU"
    CONFIGURATION_MANAGEMENT = "CM"
    IDENTIFICATION_AUTHENTICATION = "IA"
    SYSTEM_INFORMATION_INTEGRITY = "SI"


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

            # Check for addon profiles
            monitoring_enabled = False
            azure_policy_enabled = False
            if hasattr(cluster, 'addon_profiles') and cluster.addon_profiles:
                monitoring_enabled = cluster.addon_profiles.get('omsagent', {}).enabled if cluster.addon_profiles.get('omsagent') else False
                azure_policy_enabled = cluster.addon_profiles.get('azurepolicy', {}).enabled if cluster.addon_profiles.get('azurepolicy') else False

            return {
                'source': 'AKS API',
                'cluster_name': cluster.name,
                'kubernetes_version': cluster.kubernetes_version,
                'rbac_enabled': cluster.enable_rbac,
                'azure_ad_enabled': cluster.aad_profile is not None,
                'network_policy': cluster.network_profile.network_policy if cluster.network_profile else None,
                'private_cluster': cluster.api_server_access_profile.enable_private_cluster if cluster.api_server_access_profile else False,
                'authorized_ip_ranges': cluster.api_server_access_profile.authorized_ip_ranges if cluster.api_server_access_profile else [],
                'encryption_at_rest': cluster.disk_encryption_set_id is not None,
                'monitoring_enabled': monitoring_enabled,
                'azure_policy_enabled': azure_policy_enabled,
                'auto_upgrade_enabled': cluster.auto_upgrade_profile is not None if hasattr(cluster, 'auto_upgrade_profile') else False
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

    async def collect_container_images(self) -> Dict:
        """Collect container image information"""
        logger.info("Collecting container image information...")
        try:
            pods = self.v1.list_pod_for_all_namespaces()

            images = set()
            outdated_images = []

            for pod in pods.items:
                for container in pod.spec.containers:
                    images.add(container.image)
                    # Check for latest tag (not recommended)
                    if ':latest' in container.image or ':' not in container.image:
                        outdated_images.append({
                            'pod': pod.metadata.name,
                            'namespace': pod.metadata.namespace,
                            'container': container.name,
                            'image': container.image,
                            'issue': 'Using latest tag or no tag specified'
                        })

            return {
                'source': 'Container Images',
                'total_unique_images': len(images),
                'images_with_issues': len(outdated_images),
                'issues': outdated_images[:20]
            }
        except Exception as e:
            logger.error(f"Error collecting container images: {e}")
            return {'source': 'Container Images', 'error': str(e)}


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
            },
            'AU-2': {
                'name': 'Event Logging',
                'family': 'AU',
                'description': 'Identify the types of events that the system is capable of logging'
            },
            'AU-3': {
                'name': 'Content of Audit Records',
                'family': 'AU',
                'description': 'Ensure audit records contain information to establish what, when, where, and who'
            },
            'AU-6': {
                'name': 'Audit Record Review, Analysis, and Reporting',
                'family': 'AU',
                'description': 'Review and analyze system audit records for indications of inappropriate activity'
            },
            'AU-9': {
                'name': 'Protection of Audit Information',
                'family': 'AU',
                'description': 'Protect audit information and audit logging tools from unauthorized access'
            },
            'AU-12': {
                'name': 'Audit Record Generation',
                'family': 'AU',
                'description': 'Provide audit record generation capability for defined auditable events'
            },
            'CM-2': {
                'name': 'Baseline Configuration',
                'family': 'CM',
                'description': 'Develop, document, and maintain baseline configurations'
            },
            'CM-3': {
                'name': 'Configuration Change Control',
                'family': 'CM',
                'description': 'Determine and control changes to system configuration'
            },
            'CM-6': {
                'name': 'Configuration Settings',
                'family': 'CM',
                'description': 'Establish and document configuration settings for system components'
            },
            'CM-7': {
                'name': 'Least Functionality',
                'family': 'CM',
                'description': 'Configure the system to provide only essential capabilities'
            },
            'IA-2': {
                'name': 'Identification and Authentication',
                'family': 'IA',
                'description': 'Uniquely identify and authenticate organizational users'
            },
            'IA-4': {
                'name': 'Identifier Management',
                'family': 'IA',
                'description': 'Manage system identifiers for users and devices'
            },
            'IA-5': {
                'name': 'Authenticator Management',
                'family': 'IA',
                'description': 'Manage system authenticators including passwords and tokens'
            },
            'SI-2': {
                'name': 'Flaw Remediation',
                'family': 'SI',
                'description': 'Identify, report, and correct system flaws'
            },
            'SI-3': {
                'name': 'Malicious Code Protection',
                'family': 'SI',
                'description': 'Implement malicious code protection mechanisms'
            },
            'SI-4': {
                'name': 'System Monitoring',
                'family': 'SI',
                'description': 'Monitor the system to detect attacks and unauthorized activity'
            },
            'SI-5': {
                'name': 'Security Alerts and Advisories',
                'family': 'SI',
                'description': 'Receive and respond to system security alerts and advisories'
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

    # AU (Audit and Accountability) Controls

    def assess_au_2(self, evidence_data: Dict) -> ControlAssessment:
        """Assess AU-2: Event Logging"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0

        aks_config = evidence_data.get('aks_configuration', {})

        if not aks_config.get('monitoring_enabled'):
            gaps.append("Azure Monitor for containers not enabled")
            recommendations.append("Enable Azure Monitor for containers to collect audit logs")
            risk_score += 50
        else:
            evidence_ids.append("azure_monitor_enabled")

        if aks_config.get('monitoring_enabled'):
            narrative = "AKS cluster has Azure Monitor for containers enabled, providing comprehensive logging " \
                       "of cluster events, container logs, and performance metrics. " \
                       "Control plane logs are available through Azure Monitor."
        else:
            narrative = "Event logging capabilities are limited. Azure Monitor for containers is not enabled, " \
                       "reducing visibility into cluster activities and security events."

        recommendations.append("Enable diagnostic settings to capture API server, audit, and authenticator logs")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED

        return ControlAssessment(
            control_id='AU-2',
            control_name=self.controls['AU-2']['name'],
            family='AU',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_au_12(self, evidence_data: Dict) -> ControlAssessment:
        """Assess AU-12: Audit Record Generation"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0

        aks_config = evidence_data.get('aks_configuration', {})

        if aks_config.get('monitoring_enabled'):
            evidence_ids.append("monitoring_enabled")
            narrative = "Audit record generation is implemented through Azure Monitor for containers, " \
                       "which captures container logs, cluster metrics, and Kubernetes events. "
            risk_score = 10
        else:
            gaps.append("Azure Monitor not enabled - limited audit record generation")
            recommendations.append("Enable Azure Monitor to generate comprehensive audit records")
            risk_score = 60
            narrative = "Audit record generation is not fully implemented. Without Azure Monitor, " \
                       "the cluster lacks comprehensive auditing capabilities."

        recommendations.append("Configure diagnostic logs for kube-apiserver and kube-audit")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED

        return ControlAssessment(
            control_id='AU-12',
            control_name=self.controls['AU-12']['name'],
            family='AU',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_au_3(self, evidence_data: Dict) -> ControlAssessment:
        """Assess AU-3: Content of Audit Records"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 10  # Base risk for partial implementation

        aks_config = evidence_data.get('aks_configuration', {})

        if aks_config.get('monitoring_enabled'):
            evidence_ids.append("azure_monitor_enabled")
            narrative = "Azure Monitor for containers captures audit record content including timestamps, " \
                       "event types, source locations, user identities, and event outcomes. " \
                       "Logs include pod events, container logs, and Kubernetes API server audit logs. "
        else:
            gaps.append("Azure Monitor not enabled - limited audit record content")
            recommendations.append("Enable Azure Monitor to capture comprehensive audit record content")
            risk_score += 40
            narrative = "Audit record content is limited without Azure Monitor. "

        gaps.append("Verify diagnostic settings capture all required audit fields (who, what, when, where, outcome)")
        recommendations.append("Enable Kubernetes audit policy to capture detailed API server events")
        recommendations.append("Configure log retention to meet compliance requirements")
        recommendations.append("Ensure audit logs include user identity, timestamp, source IP, and action outcome")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED

        return ControlAssessment(
            control_id='AU-3',
            control_name=self.controls['AU-3']['name'],
            family='AU',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_au_6(self, evidence_data: Dict) -> ControlAssessment:
        """Assess AU-6: Audit Record Review, Analysis, and Reporting"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 30  # Base risk as this requires manual processes

        aks_config = evidence_data.get('aks_configuration', {})
        defender_recs = evidence_data.get('defender_recommendations', {})

        if aks_config.get('monitoring_enabled'):
            evidence_ids.append("azure_monitor_enabled")
            narrative = "Azure Monitor provides capabilities for audit record review through Log Analytics queries. "
        else:
            gaps.append("Azure Monitor not enabled - cannot review audit records")
            risk_score += 40
            narrative = "Audit record review capabilities are not implemented. "

        if defender_recs.get('total_recommendations', 0) > 0:
            evidence_ids.append("defender_analysis")
            narrative += "Microsoft Defender for Cloud provides automated security analysis and reporting. "
        else:
            gaps.append("Microsoft Defender not providing security analysis")
            risk_score += 20

        gaps.append("Manual verification needed for regular audit log review process")
        gaps.append("Verify anomaly detection and alerting is configured")

        recommendations.append("Establish regular audit log review schedule")
        recommendations.append("Configure Azure Monitor alerts for security events")
        recommendations.append("Implement SIEM integration for centralized log analysis")
        recommendations.append("Use Azure Sentinel for advanced threat detection and investigation")
        recommendations.append("Define and document audit review procedures and responsibilities")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED

        return ControlAssessment(
            control_id='AU-6',
            control_name=self.controls['AU-6']['name'],
            family='AU',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_au_9(self, evidence_data: Dict) -> ControlAssessment:
        """Assess AU-9: Protection of Audit Information"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 20  # Base risk

        aks_config = evidence_data.get('aks_configuration', {})
        rbac_config = evidence_data.get('rbac_configuration', {})

        if aks_config.get('rbac_enabled'):
            evidence_ids.append("rbac_enabled")
            narrative = "Audit information is protected through RBAC controls limiting access to logs. " \
                       "Azure Monitor Log Analytics workspaces use Azure AD authentication and RBAC. "
        else:
            gaps.append("RBAC not enabled - audit information may not be properly protected")
            risk_score += 40
            narrative = "RBAC is not enabled, limiting protection of audit information. "

        if aks_config.get('monitoring_enabled'):
            evidence_ids.append("azure_monitor_protection")
            narrative += "Logs are stored in Azure Monitor with built-in retention and access controls. "
            risk_score = min(risk_score, 30)
        else:
            gaps.append("Azure Monitor not enabled - logs not centrally protected")
            risk_score += 30

        gaps.append("Verify Log Analytics workspace access is restricted to authorized personnel")
        gaps.append("Verify log immutability and tamper-evident features are enabled")

        recommendations.append("Configure Log Analytics workspace with dedicated RBAC roles")
        recommendations.append("Enable Azure Policy to prevent audit log deletion")
        recommendations.append("Implement log backup and archival procedures")
        recommendations.append("Configure alerts for unauthorized audit log access attempts")
        recommendations.append("Use Azure Key Vault for encryption keys protecting audit data")
        recommendations.append("Enable diagnostic log integrity verification")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED

        return ControlAssessment(
            control_id='AU-9',
            control_name=self.controls['AU-9']['name'],
            family='AU',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    # CM (Configuration Management) Controls

    def assess_cm_2(self, evidence_data: Dict) -> ControlAssessment:
        """Assess CM-2: Baseline Configuration"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0

        aks_config = evidence_data.get('aks_configuration', {})
        azure_policy = evidence_data.get('azure_policy', {})

        if aks_config.get('azure_policy_enabled'):
            evidence_ids.append("azure_policy_enabled")
            narrative = "Baseline configuration management is implemented through Azure Policy for AKS. "
            risk_score = 10
        else:
            gaps.append("Azure Policy for AKS not enabled")
            recommendations.append("Enable Azure Policy add-on to enforce baseline configurations")
            risk_score += 40
            narrative = "Baseline configuration management is limited without Azure Policy. "

        narrative += f"Cluster running Kubernetes version {aks_config.get('kubernetes_version', 'unknown')}. "

        if not aks_config.get('auto_upgrade_enabled'):
            gaps.append("Auto-upgrade not enabled for cluster")
            recommendations.append("Enable auto-upgrade to maintain baseline configuration currency")
            risk_score += 20

        recommendations.append("Document and maintain Infrastructure as Code for cluster configuration")
        recommendations.append("Implement GitOps practices for configuration management")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED

        return ControlAssessment(
            control_id='CM-2',
            control_name=self.controls['CM-2']['name'],
            family='CM',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_cm_7(self, evidence_data: Dict) -> ControlAssessment:
        """Assess CM-7: Least Functionality"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0

        aks_config = evidence_data.get('aks_configuration', {})
        pod_security = evidence_data.get('pod_security', {})

        # Check if cluster is private
        if aks_config.get('private_cluster'):
            evidence_ids.append("private_cluster")
            narrative = "Cluster implements least functionality through private cluster configuration, " \
                       "limiting API server exposure. "
        else:
            gaps.append("Cluster API server is publicly accessible")
            recommendations.append("Consider enabling private cluster to reduce attack surface")
            risk_score += 30
            narrative = "Cluster API server is publicly accessible. "

        # Check for authorized IP ranges
        auth_ranges = aks_config.get('authorized_ip_ranges', [])
        if auth_ranges and not aks_config.get('private_cluster'):
            evidence_ids.append("authorized_ip_ranges")
            narrative += f"API access is restricted to {len(auth_ranges)} authorized IP ranges. "
        elif not aks_config.get('private_cluster'):
            gaps.append("No authorized IP ranges configured for public cluster")
            recommendations.append("Configure authorized IP ranges to restrict API server access")
            risk_score += 20

        # Check pod security
        security_issues = pod_security.get('security_issues', 0)
        if security_issues > 0:
            gaps.append(f"{security_issues} pods with unnecessary privileges detected")
            recommendations.append("Review pod security contexts to enforce least privilege")
            risk_score += min(security_issues * 2, 30)

        recommendations.append("Disable unused Kubernetes features and APIs")
        recommendations.append("Use Pod Security Standards to enforce least functionality")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED

        return ControlAssessment(
            control_id='CM-7',
            control_name=self.controls['CM-7']['name'],
            family='CM',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_cm_3(self, evidence_data: Dict) -> ControlAssessment:
        """Assess CM-3: Configuration Change Control"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 30  # Base risk as this requires organizational processes

        aks_config = evidence_data.get('aks_configuration', {})
        azure_policy = evidence_data.get('azure_policy', {})

        if aks_config.get('azure_policy_enabled'):
            evidence_ids.append("azure_policy_change_control")
            narrative = "Configuration change control is partially implemented through Azure Policy, " \
                       "which enforces configuration standards and prevents unauthorized changes. "
            risk_score = 20
        else:
            gaps.append("Azure Policy not enabled - limited change control enforcement")
            recommendations.append("Enable Azure Policy to enforce configuration change controls")
            risk_score += 30
            narrative = "Configuration change control lacks automated enforcement without Azure Policy. "

        # Check for policy compliance
        if azure_policy.get('non_compliant_count', 0) > 0:
            gaps.append(f"{azure_policy.get('non_compliant_count')} policy violations detected")
            recommendations.append("Address non-compliant resources to enforce change control")
            risk_score += 20

        gaps.append("Manual verification needed for change approval and documentation processes")
        gaps.append("Verify GitOps or Infrastructure as Code practices are in place")

        recommendations.append("Implement GitOps workflow for infrastructure changes")
        recommendations.append("Use Azure DevOps or GitHub Actions for change tracking and approval")
        recommendations.append("Enable Azure Resource Manager locks on critical resources")
        recommendations.append("Implement change advisory board (CAB) process")
        recommendations.append("Use Kubernetes admission controllers for policy enforcement")
        recommendations.append("Document and enforce change management procedures")

        status = ComplianceStatus.PARTIALLY_IMPLEMENTED

        return ControlAssessment(
            control_id='CM-3',
            control_name=self.controls['CM-3']['name'],
            family='CM',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_cm_6(self, evidence_data: Dict) -> ControlAssessment:
        """Assess CM-6: Configuration Settings"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 20  # Base risk

        aks_config = evidence_data.get('aks_configuration', {})
        azure_policy = evidence_data.get('azure_policy', {})
        pod_security = evidence_data.get('pod_security', {})

        narrative = f"AKS cluster is configured with Kubernetes version {aks_config.get('kubernetes_version', 'unknown')}. "

        if aks_config.get('azure_policy_enabled'):
            evidence_ids.append("azure_policy_settings")
            narrative += "Azure Policy enforces mandatory configuration settings. "
        else:
            gaps.append("Azure Policy not enabled to enforce configuration settings")
            risk_score += 30

        # Check RBAC
        if aks_config.get('rbac_enabled'):
            evidence_ids.append("rbac_configured")
            narrative += "RBAC is enabled enforcing access control settings. "
        else:
            gaps.append("RBAC not enabled")
            risk_score += 30

        # Check network configuration
        if aks_config.get('network_policy'):
            evidence_ids.append("network_policy_configured")
            narrative += f"Network policy ({aks_config.get('network_policy')}) is configured. "
        else:
            gaps.append("Network policy not configured")
            recommendations.append("Enable network policy (Azure, Calico, or Cilium)")
            risk_score += 20

        # Check encryption
        if aks_config.get('encryption_at_rest'):
            evidence_ids.append("encryption_configured")
            narrative += "Encryption at rest is configured. "
        else:
            gaps.append("Disk encryption not configured")
            risk_score += 20

        # Check pod security issues
        if pod_security.get('security_issues', 0) > 0:
            gaps.append(f"{pod_security.get('security_issues')} pods with non-compliant security settings")
            risk_score += 10

        gaps.append("Verify security configuration settings are documented and maintained")

        recommendations.append("Document all security-relevant configuration settings")
        recommendations.append("Implement configuration drift detection")
        recommendations.append("Use CIS Kubernetes Benchmark for configuration hardening")
        recommendations.append("Enable Pod Security Standards enforcement")
        recommendations.append("Configure security contexts for all workloads")
        recommendations.append("Implement automated configuration compliance scanning")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED

        return ControlAssessment(
            control_id='CM-6',
            control_name=self.controls['CM-6']['name'],
            family='CM',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    # IA (Identification and Authentication) Controls

    def assess_ia_2(self, evidence_data: Dict) -> ControlAssessment:
        """Assess IA-2: Identification and Authentication"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0

        aks_config = evidence_data.get('aks_configuration', {})
        rbac_config = evidence_data.get('rbac_configuration', {})

        if aks_config.get('azure_ad_enabled'):
            evidence_ids.append("azure_ad_enabled")
            narrative = "Identification and authentication is implemented through Azure AD integration, " \
                       "providing centralized identity management and multi-factor authentication capabilities. "
            risk_score = 0
        else:
            gaps.append("Azure AD integration not enabled")
            recommendations.append("Enable Azure AD integration for strong authentication")
            risk_score += 50
            narrative = "Azure AD integration is not enabled. Cluster relies on Kubernetes native authentication " \
                       "which lacks enterprise identity management capabilities. "

        if not aks_config.get('rbac_enabled'):
            gaps.append("RBAC not enabled")
            recommendations.append("Enable RBAC for proper authorization after authentication")
            risk_score += 30

        if rbac_config.get('cluster_role_bindings_count', 0) > 0:
            evidence_ids.append("rbac_configured")
            narrative += f"RBAC is configured with {rbac_config.get('cluster_role_bindings_count')} cluster role bindings."

        recommendations.append("Implement service mesh with mutual TLS for service-to-service authentication")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED

        return ControlAssessment(
            control_id='IA-2',
            control_name=self.controls['IA-2']['name'],
            family='IA',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_ia_5(self, evidence_data: Dict) -> ControlAssessment:
        """Assess IA-5: Authenticator Management"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 20  # Base risk for secret management

        aks_config = evidence_data.get('aks_configuration', {})

        narrative = "Authenticator management in AKS includes management of service account tokens, " \
                   "Azure AD credentials, and Kubernetes secrets. "

        if aks_config.get('azure_ad_enabled'):
            evidence_ids.append("azure_ad_managed_auth")
            narrative += "Azure AD manages user authentication credentials with enterprise-grade policies. "
        else:
            gaps.append("Azure AD not enabled - limited authenticator management")
            risk_score += 30

        recommendations.append("Implement Azure Key Vault for Kubernetes secrets management")
        recommendations.append("Enable automatic service account token rotation")
        recommendations.append("Use Azure Managed Identities for pod authentication to Azure services")
        recommendations.append("Implement secret scanning in CI/CD pipelines")

        gaps.append("Manual verification needed for secret rotation policies")
        gaps.append("Verify Key Vault integration for secrets management")

        status = ComplianceStatus.PARTIALLY_IMPLEMENTED

        return ControlAssessment(
            control_id='IA-5',
            control_name=self.controls['IA-5']['name'],
            family='IA',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_ia_4(self, evidence_data: Dict) -> ControlAssessment:
        """Assess IA-4: Identifier Management"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 20  # Base risk

        aks_config = evidence_data.get('aks_configuration', {})
        rbac_config = evidence_data.get('rbac_configuration', {})

        if aks_config.get('azure_ad_enabled'):
            evidence_ids.append("azure_ad_identifier_mgmt")
            narrative = "Identifier management is implemented through Azure AD integration, " \
                       "providing centralized management of user and service identities. " \
                       "Azure AD assigns and manages unique identifiers for all users. "
        else:
            gaps.append("Azure AD not enabled - limited identifier management capabilities")
            risk_score += 40
            narrative = "Identifier management relies on Kubernetes native service accounts " \
                       "without centralized Azure AD management. "

        if aks_config.get('rbac_enabled'):
            evidence_ids.append("rbac_identifier_enforcement")
            narrative += "RBAC enforces identifier-based access controls. "
        else:
            gaps.append("RBAC not enabled - identifiers not enforced for access control")
            risk_score += 30

        # Check service accounts
        if rbac_config.get('cluster_role_bindings_count', 0) > 0:
            narrative += f"Cluster has {rbac_config.get('cluster_role_bindings_count')} role bindings managing identity assignments. "

        gaps.append("Verify service account lifecycle management procedures are in place")
        gaps.append("Verify unique identifiers are assigned to all users and services")

        recommendations.append("Implement automated service account provisioning and deprovisioning")
        recommendations.append("Use Azure Managed Identities for pod identities")
        recommendations.append("Enforce naming conventions for service accounts")
        recommendations.append("Implement regular review of service account usage")
        recommendations.append("Disable or remove unused service accounts")
        recommendations.append("Use Azure AD Pod Identity or Workload Identity for cloud resource access")
        recommendations.append("Document identifier assignment and management procedures")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED

        return ControlAssessment(
            control_id='IA-4',
            control_name=self.controls['IA-4']['name'],
            family='IA',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    # SI (System and Information Integrity) Controls

    def assess_si_2(self, evidence_data: Dict) -> ControlAssessment:
        """Assess SI-2: Flaw Remediation"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0

        aks_config = evidence_data.get('aks_configuration', {})
        defender_recs = evidence_data.get('defender_recommendations', {})
        container_images = evidence_data.get('container_images', {})

        # Check auto-upgrade
        if aks_config.get('auto_upgrade_enabled'):
            evidence_ids.append("auto_upgrade_enabled")
            narrative = "Flaw remediation is partially automated through cluster auto-upgrade. "
        else:
            gaps.append("Auto-upgrade not enabled for AKS cluster")
            recommendations.append("Enable auto-upgrade to automatically patch cluster components")
            risk_score += 30
            narrative = "Cluster does not have auto-upgrade enabled. "

        narrative += f"Cluster running Kubernetes {aks_config.get('kubernetes_version', 'unknown')}. "

        # Check Defender recommendations
        unhealthy = defender_recs.get('unhealthy', 0)
        if unhealthy > 0:
            gaps.append(f"{unhealthy} unhealthy security recommendations from Defender")
            recommendations.append("Address security recommendations from Microsoft Defender for Cloud")
            risk_score += min(unhealthy * 5, 40)

        # Check container images
        images_with_issues = container_images.get('images_with_issues', 0)
        if images_with_issues > 0:
            gaps.append(f"{images_with_issues} containers using 'latest' or untagged images")
            recommendations.append("Use specific image tags for better version control and flaw tracking")
            risk_score += min(images_with_issues * 2, 20)

        recommendations.append("Implement container image scanning in CI/CD pipeline")
        recommendations.append("Establish patch management process for container images")
        recommendations.append("Monitor CVE databases for vulnerabilities in deployed images")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED

        return ControlAssessment(
            control_id='SI-2',
            control_name=self.controls['SI-2']['name'],
            family='SI',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_si_3(self, evidence_data: Dict) -> ControlAssessment:
        """Assess SI-3: Malicious Code Protection"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 30  # Base risk as this needs manual verification

        defender_recs = evidence_data.get('defender_recommendations', {})

        narrative = "Malicious code protection for AKS should be implemented through Microsoft Defender for Containers, " \
                   "which provides runtime threat detection and image vulnerability scanning. "

        total_recs = defender_recs.get('total_recommendations', 0)
        if total_recs > 0:
            evidence_ids.append("defender_enabled")
            narrative += f"Microsoft Defender is active with {total_recs} security assessments. "
            risk_score = 20
        else:
            gaps.append("Microsoft Defender for Containers assessments not detected")
            recommendations.append("Enable and configure Microsoft Defender for Containers")
            risk_score = 60

        gaps.append("Manual verification needed for runtime threat detection configuration")
        gaps.append("Verify admission controller policies block untrusted images")

        recommendations.append("Implement image scanning before deployment")
        recommendations.append("Use admission controllers to enforce image security policies")
        recommendations.append("Enable runtime threat detection in Microsoft Defender")
        recommendations.append("Implement network segmentation to limit malware spread")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED

        return ControlAssessment(
            control_id='SI-3',
            control_name=self.controls['SI-3']['name'],
            family='SI',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_si_4(self, evidence_data: Dict) -> ControlAssessment:
        """Assess SI-4: System Monitoring"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 0

        aks_config = evidence_data.get('aks_configuration', {})
        defender_recs = evidence_data.get('defender_recommendations', {})

        if aks_config.get('monitoring_enabled'):
            evidence_ids.append("azure_monitor_enabled")
            narrative = "System monitoring is implemented through Azure Monitor for containers, " \
                       "providing real-time monitoring of cluster health, resource utilization, and application performance. "
            risk_score = 10
        else:
            gaps.append("Azure Monitor for containers not enabled")
            recommendations.append("Enable Azure Monitor for comprehensive system monitoring")
            risk_score += 50
            narrative = "System monitoring capabilities are limited without Azure Monitor for containers. "

        if defender_recs.get('total_recommendations', 0) > 0:
            evidence_ids.append("defender_monitoring")
            narrative += "Microsoft Defender provides security monitoring and threat detection. "
        else:
            gaps.append("Microsoft Defender security monitoring not detected")
            recommendations.append("Enable Microsoft Defender for Containers for security monitoring")
            risk_score += 20

        recommendations.append("Configure alerts for security events and anomalies")
        recommendations.append("Implement log aggregation and SIEM integration")
        recommendations.append("Set up monitoring dashboards for security metrics")
        recommendations.append("Enable Azure Sentinel for advanced threat detection")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED if risk_score > 0 else \
                 ComplianceStatus.IMPLEMENTED

        return ControlAssessment(
            control_id='SI-4',
            control_name=self.controls['SI-4']['name'],
            family='SI',
            status=status,
            implementation_narrative=narrative,
            evidence_ids=evidence_ids,
            gaps=gaps,
            recommendations=recommendations,
            last_assessed=datetime.now(),
            risk_score=min(risk_score, 100)
        )

    def assess_si_5(self, evidence_data: Dict) -> ControlAssessment:
        """Assess SI-5: Security Alerts and Advisories"""
        gaps = []
        recommendations = []
        evidence_ids = []
        risk_score = 30  # Base risk

        aks_config = evidence_data.get('aks_configuration', {})
        defender_recs = evidence_data.get('defender_recommendations', {})

        if defender_recs.get('total_recommendations', 0) > 0:
            evidence_ids.append("defender_alerts")
            narrative = "Security alerts and advisories are received through Microsoft Defender for Cloud, " \
                       f"which provides {defender_recs.get('total_recommendations')} active security assessments and recommendations. "
            risk_score = 20
        else:
            gaps.append("Microsoft Defender for Cloud not providing security alerts")
            recommendations.append("Enable Microsoft Defender for Containers for security alerts")
            risk_score += 40
            narrative = "Security alerts and advisories capabilities are limited. "

        if aks_config.get('monitoring_enabled'):
            evidence_ids.append("azure_monitor_alerts")
            narrative += "Azure Monitor can be configured to send alerts based on log queries and metrics. "
        else:
            gaps.append("Azure Monitor not enabled - cannot configure custom security alerts")
            risk_score += 20

        # Check auto-upgrade for advisory response
        if aks_config.get('auto_upgrade_enabled'):
            evidence_ids.append("auto_upgrade_advisories")
            narrative += "Auto-upgrade is enabled to automatically respond to security advisories. "
        else:
            gaps.append("Auto-upgrade not enabled - manual response required for security advisories")
            recommendations.append("Enable auto-upgrade to automatically respond to Kubernetes security advisories")
            risk_score += 20

        gaps.append("Verify security advisory subscription and monitoring processes")
        gaps.append("Verify incident response procedures for security alerts")

        recommendations.append("Subscribe to Azure Service Health alerts")
        recommendations.append("Subscribe to Kubernetes security announcement mailing lists")
        recommendations.append("Configure Azure Monitor alert rules for security events")
        recommendations.append("Integrate security alerts with incident response system")
        recommendations.append("Establish security advisory review and response procedures")
        recommendations.append("Configure Azure Security Center continuous export to SIEM")
        recommendations.append("Document security alert escalation and response procedures")

        status = ComplianceStatus.NOT_IMPLEMENTED if risk_score > 50 else \
                 ComplianceStatus.PARTIALLY_IMPLEMENTED

        return ControlAssessment(
            control_id='SI-5',
            control_name=self.controls['SI-5']['name'],
            family='SI',
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
        azure_policy, defender_recs, aks_config, rbac_config, network_policies, pod_security, container_images = \
            await asyncio.gather(
                self.azure_collector.collect_policy_compliance(),
                self.azure_collector.collect_defender_recommendations(),
                self.azure_collector.collect_aks_configuration(),
                self.k8s_collector.collect_rbac_configuration(),
                self.k8s_collector.collect_network_policies(),
                self.k8s_collector.collect_pod_security(),
                self.k8s_collector.collect_container_images()
            )

        evidence_data = {
            'azure_policy': azure_policy,
            'defender_recommendations': defender_recs,
            'aks_configuration': aks_config,
            'rbac_configuration': rbac_config,
            'network_policies': network_policies,
            'pod_security': pod_security,
            'container_images': container_images,
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
            # Access Control (AC)
            self.assessor.assess_ac_2(evidence_data),
            self.assessor.assess_ac_3(evidence_data),
            self.assessor.assess_ac_6(evidence_data),
            # System and Communications Protection (SC)
            self.assessor.assess_sc_7(evidence_data),
            self.assessor.assess_sc_8(evidence_data),
            self.assessor.assess_sc_28(evidence_data),
            # Audit and Accountability (AU)
            self.assessor.assess_au_2(evidence_data),
            self.assessor.assess_au_3(evidence_data),
            self.assessor.assess_au_6(evidence_data),
            self.assessor.assess_au_9(evidence_data),
            self.assessor.assess_au_12(evidence_data),
            # Configuration Management (CM)
            self.assessor.assess_cm_2(evidence_data),
            self.assessor.assess_cm_3(evidence_data),
            self.assessor.assess_cm_6(evidence_data),
            self.assessor.assess_cm_7(evidence_data),
            # Identification and Authentication (IA)
            self.assessor.assess_ia_2(evidence_data),
            self.assessor.assess_ia_4(evidence_data),
            self.assessor.assess_ia_5(evidence_data),
            # System and Information Integrity (SI)
            self.assessor.assess_si_2(evidence_data),
            self.assessor.assess_si_3(evidence_data),
            self.assessor.assess_si_4(evidence_data),
            self.assessor.assess_si_5(evidence_data)
        ]
        
        # Store all assessments
        for assessment in assessments:
            self.repository.store_assessment(assessment)
        
        return assessments
    
    async def run_assessment(self) -> Dict:
        """Run complete compliance assessment"""
        logger.info("=" * 60)
        logger.info("CONTINUOUS ATO ASSESSMENT STARTING")
        logger.info("=" * 60)
        
        # Collect evidence
        evidence_data = await self.collect_all_evidence()
        
        # Assess controls
        assessments = await self.assess_all_controls(evidence_data)
        
        # Generate summary
        total = len(assessments)
        implemented = len([a for a in assessments if a.status == ComplianceStatus.IMPLEMENTED])
        partial = len([a for a in assessments if a.status == ComplianceStatus.PARTIALLY_IMPLEMENTED])
        not_impl = len([a for a in assessments if a.status == ComplianceStatus.NOT_IMPLEMENTED])
        
        compliance_percentage = (implemented + (partial * 0.5)) / total * 100 if total > 0 else 0
        avg_risk_score = sum(a.risk_score for a in assessments) / total if total > 0 else 0
        
        summary = {
            'total_controls': total,
            'implemented': implemented,
            'partially_implemented': partial,
            'not_implemented': not_impl,
            'compliance_percentage': round(compliance_percentage, 2),
            'average_risk_score': round(avg_risk_score, 2),
            'assessment_date': datetime.now().isoformat()
        }
        
        logger.info("=" * 60)
        logger.info(f"ASSESSMENT COMPLETE - Compliance: {compliance_percentage:.1f}%")
        logger.info("=" * 60)
        
        return {
            'summary': summary,
            'assessments': assessments,
            'evidence_data': evidence_data
        }
