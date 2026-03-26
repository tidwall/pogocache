package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PogoCacheInstanceSpec defines the desired state of PogoCacheInstance.
type PogoCacheInstanceSpec struct {
	// Replicas is the number of pod replicas. Defaults to 1.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=0
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// Image is the container image for pogocache. Defaults to "pogocache/pogocache:latest".
	// +kubebuilder:default="pogocache/pogocache:latest"
	// +optional
	Image string `json:"image,omitempty"`

	// Port is the port pogocache listens on. Defaults to 9401.
	// +kubebuilder:default=9401
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty"`

	// Threads sets the number of worker threads (--threads). Defaults to CPU count.
	// +kubebuilder:validation:Minimum=1
	// +optional
	Threads *int32 `json:"threads,omitempty"`

	// MaxMemory sets the memory limit, e.g. "80%" or "4gb" (--maxmemory).
	// +optional
	MaxMemory string `json:"maxMemory,omitempty"`

	// Evict controls whether keys are evicted when maxmemory is reached (--evict).
	// +optional
	Evict *bool `json:"evict,omitempty"`

	// MaxConns sets the maximum number of concurrent connections (--maxconns).
	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxConns *int32 `json:"maxConns,omitempty"`

	// Persist configures on-disk persistence for the cache.
	// +optional
	Persist *PersistConfig `json:"persist,omitempty"`

	// Auth configures authentication for the cache.
	// +optional
	Auth *AuthConfig `json:"auth,omitempty"`

	// TLS configures TLS termination for the cache.
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`

	// Resources defines compute resource requests and limits for the cache container.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// ExtraFlags are appended verbatim to the POGOCACHE_EXTRA_FLAGS environment variable.
	// +optional
	ExtraFlags string `json:"extraFlags,omitempty"`

	// NodeSelector is a map of node labels used for pod scheduling.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations define pod tolerations for scheduling onto tainted nodes.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity defines scheduling affinity rules for the cache pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
}

// PersistConfig configures on-disk persistence backed by a PersistentVolumeClaim.
type PersistConfig struct {
	// Path is the file path inside the container used for persistence (--persist).
	// +kubebuilder:validation:MinLength=1
	Path string `json:"path"`

	// StorageClassName is the name of the StorageClass to use for the PVC.
	// If not set, the cluster default StorageClass is used.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// Size is the requested storage capacity, e.g. "1Gi".
	Size resource.Quantity `json:"size"`
}

// AuthConfig configures authentication credentials for the cache.
// SecretRef takes precedence over the inline Password field.
type AuthConfig struct {
	// Password is a plaintext authentication token. Prefer SecretRef for production use.
	// +optional
	Password string `json:"password,omitempty"`

	// SecretRef references a key in a Kubernetes Secret containing the auth password.
	// When set, this takes precedence over the Password field.
	// +optional
	SecretRef *corev1.SecretKeySelector `json:"secretRef,omitempty"`
}

// TLSConfig configures TLS for the cache.
type TLSConfig struct {
	// Port is the port pogocache listens on for TLS connections (--tlsport).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// SecretRef is the name of a Kubernetes Secret in the same namespace containing
	// tls.crt (certificate), tls.key (private key), and optionally ca.crt (CA cert).
	// +kubebuilder:validation:MinLength=1
	SecretRef string `json:"secretRef"`
}

// PogoCacheInstanceStatus defines the observed state of PogoCacheInstance.
type PogoCacheInstanceStatus struct {
	// ReadyReplicas is the number of pods with a Ready condition.
	ReadyReplicas int32 `json:"readyReplicas"`

	// Phase summarises the overall lifecycle state: Pending, Running, or Failed.
	// +kubebuilder:validation:Enum=Pending;Running;Failed
	Phase string `json:"phase,omitempty"`

	// Conditions provide detailed status conditions following the k8s conventions.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Phase constants for PogoCacheInstanceStatus.
const (
	PhasePending = "Pending"
	PhaseRunning = "Running"
	PhaseFailed  = "Failed"
)

// Condition type constants.
const (
	// ConditionAvailable is True when the desired number of replicas are Ready.
	ConditionAvailable = "Available"

	// ConditionProgressing is True when a rollout or scale operation is in progress.
	ConditionProgressing = "Progressing"

	// ConditionDegraded is True when the instance is not fully healthy.
	ConditionDegraded = "Degraded"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pci;pogocache,categories=cache
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=".status.readyReplicas"
// +kubebuilder:printcolumn:name="Replicas",type="integer",JSONPath=".spec.replicas"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// PogoCacheInstance is the Schema for the pogocacheinstances API.
type PogoCacheInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PogoCacheInstanceSpec   `json:"spec,omitempty"`
	Status PogoCacheInstanceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PogoCacheInstanceList contains a list of PogoCacheInstance.
type PogoCacheInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PogoCacheInstance `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PogoCacheInstance{}, &PogoCacheInstanceList{})
}
