package controllers

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cachev1alpha1 "github.com/pogocache/pogocache/operator/api/v1alpha1"
)

const (
	finalizerName  = "cache.pogocache.io/finalizer"
	tlsMountPath   = "/etc/pogocache/tls"
	dataMountPath  = "/data"
	tlsCertFile    = "tls.crt"
	tlsKeyFile     = "tls.key"
	tlsCACertFile  = "ca.crt"
)

// PogoCacheInstanceReconciler reconciles PogoCacheInstance objects.
//
// +kubebuilder:rbac:groups=cache.pogocache.io,resources=pogocacheinstances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cache.pogocache.io,resources=pogocacheinstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cache.pogocache.io,resources=pogocacheinstances/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
type PogoCacheInstanceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *PogoCacheInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cachev1alpha1.PogoCacheInstance{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Complete(r)
}

// Reconcile is the core reconciliation loop. It is called whenever the desired or
// observed state changes for a PogoCacheInstance or a resource it owns.
func (r *PogoCacheInstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	instance := &cachev1alpha1.PogoCacheInstance{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		if apierrors.IsNotFound(err) {
			// Object has been deleted; nothing to do.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching PogoCacheInstance %s: %w", req.NamespacedName, err)
	}

	// Handle deletion via finalizer so we can clean up owned resources that
	// are not automatically garbage-collected (e.g. PVCs with Retain policy).
	if instance.DeletionTimestamp != nil {
		return r.reconcileDelete(ctx, instance)
	}

	if !controllerutil.ContainsFinalizer(instance, finalizerName) {
		controllerutil.AddFinalizer(instance, finalizerName)
		if err := r.Update(ctx, instance); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Apply defaults so the rest of the reconciliation loop can be free of nil checks.
	applyDefaults(instance)

	logger.Info("reconciling PogoCacheInstance",
		"name", instance.Name,
		"namespace", instance.Namespace,
		"replicas", *instance.Spec.Replicas,
	)

	if err := r.reconcilePVC(ctx, instance); err != nil {
		return r.setFailedStatus(ctx, instance, "PVCReconcileFailed", err)
	}

	if err := r.reconcileDeployment(ctx, instance); err != nil {
		return r.setFailedStatus(ctx, instance, "DeploymentReconcileFailed", err)
	}

	if err := r.reconcileService(ctx, instance); err != nil {
		return r.setFailedStatus(ctx, instance, "ServiceReconcileFailed", err)
	}

	return r.reconcileStatus(ctx, instance)
}

// reconcileDelete removes the finalizer after any cleanup work is done.
func (r *PogoCacheInstanceReconciler) reconcileDelete(ctx context.Context, instance *cachev1alpha1.PogoCacheInstance) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("handling deletion", "name", instance.Name)

	controllerutil.RemoveFinalizer(instance, finalizerName)
	if err := r.Update(ctx, instance); err != nil {
		return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

// reconcilePVC ensures a PVC exists when persistence is configured.
func (r *PogoCacheInstanceReconciler) reconcilePVC(ctx context.Context, instance *cachev1alpha1.PogoCacheInstance) error {
	if instance.Spec.Persist == nil {
		return nil
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pvcName(instance),
			Namespace: instance.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, pvc, func() error {
		// PVC spec is immutable after creation; only set on first creation.
		if pvc.CreationTimestamp.IsZero() {
			pvc.Spec = corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: instance.Spec.Persist.Size,
					},
				},
				StorageClassName: instance.Spec.Persist.StorageClassName,
			}
		}
		return controllerutil.SetControllerReference(instance, pvc, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconciling PVC %s: %w", pvcName(instance), err)
	}
	return nil
}

// reconcileDeployment ensures the Deployment matches the desired spec.
func (r *PogoCacheInstanceReconciler) reconcileDeployment(ctx context.Context, instance *cachev1alpha1.PogoCacheInstance) error {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, dep, func() error {
		dep.Labels = resourceLabels(instance)
		dep.Spec = r.buildDeploymentSpec(instance)
		return controllerutil.SetControllerReference(instance, dep, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconciling Deployment %s: %w", instance.Name, err)
	}
	return nil
}

// reconcileService ensures the ClusterIP Service matches the desired spec.
func (r *PogoCacheInstanceReconciler) reconcileService(ctx context.Context, instance *cachev1alpha1.PogoCacheInstance) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		svc.Labels = resourceLabels(instance)
		svc.Spec.Selector = selectorLabels(instance)
		svc.Spec.Type = corev1.ServiceTypeClusterIP

		ports := []corev1.ServicePort{
			{
				Name:       "pogocache",
				Port:       instance.Spec.Port,
				TargetPort: intstr.FromInt32(instance.Spec.Port),
				Protocol:   corev1.ProtocolTCP,
			},
		}
		if instance.Spec.TLS != nil {
			ports = append(ports, corev1.ServicePort{
				Name:       "tls",
				Port:       instance.Spec.TLS.Port,
				TargetPort: intstr.FromInt32(instance.Spec.TLS.Port),
				Protocol:   corev1.ProtocolTCP,
			})
		}
		svc.Spec.Ports = ports

		return controllerutil.SetControllerReference(instance, svc, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconciling Service %s: %w", instance.Name, err)
	}
	return nil
}

// reconcileStatus reads the managed Deployment and updates the instance status.
func (r *PogoCacheInstanceReconciler) reconcileStatus(ctx context.Context, instance *cachev1alpha1.PogoCacheInstance) (ctrl.Result, error) {
	dep := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(instance), dep); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching Deployment for status: %w", err)
	}

	patch := client.MergeFrom(instance.DeepCopy())

	instance.Status.ReadyReplicas = dep.Status.ReadyReplicas

	desired := int32(1)
	if instance.Spec.Replicas != nil {
		desired = *instance.Spec.Replicas
	}

	switch {
	case dep.Status.ReadyReplicas == desired:
		instance.Status.Phase = cachev1alpha1.PhaseRunning
		meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
			Type:               cachev1alpha1.ConditionAvailable,
			Status:             metav1.ConditionTrue,
			Reason:             "DeploymentAvailable",
			Message:            fmt.Sprintf("%d/%d replicas are ready", dep.Status.ReadyReplicas, desired),
			ObservedGeneration: instance.Generation,
		})
		meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
			Type:               cachev1alpha1.ConditionProgressing,
			Status:             metav1.ConditionFalse,
			Reason:             "DeploymentAvailable",
			Message:            "Deployment has reached the desired state",
			ObservedGeneration: instance.Generation,
		})
		meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
			Type:               cachev1alpha1.ConditionDegraded,
			Status:             metav1.ConditionFalse,
			Reason:             "DeploymentAvailable",
			Message:            "Deployment is not degraded",
			ObservedGeneration: instance.Generation,
		})
	case dep.Status.ReadyReplicas == 0:
		instance.Status.Phase = cachev1alpha1.PhasePending
		meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
			Type:               cachev1alpha1.ConditionAvailable,
			Status:             metav1.ConditionFalse,
			Reason:             "DeploymentUnavailable",
			Message:            "No replicas are ready",
			ObservedGeneration: instance.Generation,
		})
		meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
			Type:               cachev1alpha1.ConditionProgressing,
			Status:             metav1.ConditionTrue,
			Reason:             "DeploymentProgressing",
			Message:            "Waiting for replicas to become ready",
			ObservedGeneration: instance.Generation,
		})
		meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
			Type:               cachev1alpha1.ConditionDegraded,
			Status:             metav1.ConditionFalse,
			Reason:             "DeploymentProgressing",
			Message:            "Deployment is progressing",
			ObservedGeneration: instance.Generation,
		})
	default:
		instance.Status.Phase = cachev1alpha1.PhaseRunning
		meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
			Type:               cachev1alpha1.ConditionAvailable,
			Status:             metav1.ConditionTrue,
			Reason:             "DeploymentPartiallyAvailable",
			Message:            fmt.Sprintf("%d/%d replicas are ready", dep.Status.ReadyReplicas, desired),
			ObservedGeneration: instance.Generation,
		})
		meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
			Type:               cachev1alpha1.ConditionProgressing,
			Status:             metav1.ConditionTrue,
			Reason:             "DeploymentProgressing",
			Message:            "Rollout is in progress",
			ObservedGeneration: instance.Generation,
		})
		meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
			Type:               cachev1alpha1.ConditionDegraded,
			Status:             metav1.ConditionFalse,
			Reason:             "DeploymentProgressing",
			Message:            "Deployment is progressing",
			ObservedGeneration: instance.Generation,
		})
	}

	if err := r.Status().Patch(ctx, instance, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching status: %w", err)
	}

	// Requeue while not fully ready so we pick up Deployment changes.
	if instance.Status.Phase != cachev1alpha1.PhaseRunning || dep.Status.ReadyReplicas != desired {
		return ctrl.Result{RequeueAfter: 10_000_000_000}, nil // 10 s
	}
	return ctrl.Result{}, nil
}

// setFailedStatus marks the instance as Failed and returns the original error.
func (r *PogoCacheInstanceReconciler) setFailedStatus(ctx context.Context, instance *cachev1alpha1.PogoCacheInstance, reason string, cause error) (ctrl.Result, error) {
	patch := client.MergeFrom(instance.DeepCopy())
	instance.Status.Phase = cachev1alpha1.PhaseFailed
	meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
		Type:               cachev1alpha1.ConditionDegraded,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            cause.Error(),
		ObservedGeneration: instance.Generation,
	})
	if err := r.Status().Patch(ctx, instance, patch); err != nil {
		log.FromContext(ctx).Error(err, "failed to patch status after reconcile error")
	}
	return ctrl.Result{}, cause
}

// buildDeploymentSpec assembles the full DeploymentSpec from the instance spec.
func (r *PogoCacheInstanceReconciler) buildDeploymentSpec(instance *cachev1alpha1.PogoCacheInstance) appsv1.DeploymentSpec {
	labels := resourceLabels(instance)
	selector := selectorLabels(instance)

	podSpec := r.buildPodSpec(instance)

	return appsv1.DeploymentSpec{
		Replicas: instance.Spec.Replicas,
		Selector: &metav1.LabelSelector{MatchLabels: selector},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: labels},
			Spec:       podSpec,
		},
		Strategy: appsv1.DeploymentStrategy{
			Type: appsv1.RollingUpdateDeploymentStrategyType,
		},
	}
}

// buildPodSpec constructs the PodSpec, wiring all volumes, env vars, and flags.
func (r *PogoCacheInstanceReconciler) buildPodSpec(instance *cachev1alpha1.PogoCacheInstance) corev1.PodSpec {
	spec := instance.Spec

	var volumes []corev1.Volume
	var volumeMounts []corev1.VolumeMount
	var envVars []corev1.EnvVar

	// --- Persistence volume ---
	if spec.Persist != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: pvcName(instance),
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "data",
			MountPath: dataMountPath,
		})
	}

	// --- TLS volume ---
	if spec.TLS != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: spec.TLS.SecretRef,
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "tls",
			MountPath: tlsMountPath,
			ReadOnly:  true,
		})
	}

	// --- Build POGOCACHE_EXTRA_FLAGS ---
	extraFlags := buildExtraFlags(instance)
	if extraFlags != "" {
		envVars = append(envVars, corev1.EnvVar{
			Name:  "POGOCACHE_EXTRA_FLAGS",
			Value: extraFlags,
		})
	}

	// --- Auth via Secret ---
	if spec.Auth != nil && spec.Auth.SecretRef != nil {
		envVars = append(envVars, corev1.EnvVar{
			Name: "POGOCACHE_AUTH_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: spec.Auth.SecretRef,
			},
		})
	}

	container := corev1.Container{
		Name:            "pogocache",
		Image:           spec.Image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports:           buildContainerPorts(instance),
		Env:             envVars,
		VolumeMounts:    volumeMounts,
		Resources:       spec.Resources,
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{
					Port: intstr.FromInt32(spec.Port),
				},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       10,
			FailureThreshold:    3,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{
					Port: intstr.FromInt32(spec.Port),
				},
			},
			InitialDelaySeconds: 15,
			PeriodSeconds:       20,
			FailureThreshold:    5,
		},
	}

	return corev1.PodSpec{
		Containers:   []corev1.Container{container},
		Volumes:      volumes,
		NodeSelector: spec.NodeSelector,
		Tolerations:  spec.Tolerations,
		Affinity:     spec.Affinity,
		// Run as non-root for defence-in-depth.
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: boolPtr(true),
			RunAsUser:    int64Ptr(65532),
			FSGroup:      int64Ptr(65532),
		},
	}
}

// buildContainerPorts returns the list of container ports to expose.
func buildContainerPorts(instance *cachev1alpha1.PogoCacheInstance) []corev1.ContainerPort {
	ports := []corev1.ContainerPort{
		{Name: "pogocache", ContainerPort: instance.Spec.Port, Protocol: corev1.ProtocolTCP},
	}
	if instance.Spec.TLS != nil {
		ports = append(ports, corev1.ContainerPort{
			Name:          "tls",
			ContainerPort: instance.Spec.TLS.Port,
			Protocol:      corev1.ProtocolTCP,
		})
	}
	return ports
}

// buildExtraFlags constructs the value for POGOCACHE_EXTRA_FLAGS from the spec.
// The container entrypoint appends this variable to the pogocache invocation.
func buildExtraFlags(instance *cachev1alpha1.PogoCacheInstance) string {
	spec := instance.Spec
	var parts []string

	if spec.Port != 0 && spec.Port != 9401 {
		parts = append(parts, fmt.Sprintf("-p %d", spec.Port))
	}

	if spec.Threads != nil {
		parts = append(parts, fmt.Sprintf("--threads %d", *spec.Threads))
	}

	if spec.MaxMemory != "" {
		parts = append(parts, fmt.Sprintf("--maxmemory %s", spec.MaxMemory))
	}

	if spec.Evict != nil {
		v := "yes"
		if !*spec.Evict {
			v = "no"
		}
		parts = append(parts, fmt.Sprintf("--evict %s", v))
	}

	if spec.MaxConns != nil {
		parts = append(parts, fmt.Sprintf("--maxconns %d", *spec.MaxConns))
	}

	if spec.Persist != nil {
		parts = append(parts, fmt.Sprintf("--persist %s", spec.Persist.Path))
	}

	// Auth: if SecretRef is set, the password is read from env at container startup.
	// We inject the flag pointing at the env var; pogocache reads it as a literal
	// string, so we use the literal value from the env var injected separately.
	// For Secret-backed auth, we use the env var POGOCACHE_AUTH_PASSWORD and append
	// the flag using shell expansion. Since the entrypoint is pogocache itself (not
	// a shell), we inject the password via a plain env var and the --auth flag here
	// only when a literal password is provided in spec.
	if spec.Auth != nil && spec.Auth.SecretRef == nil && spec.Auth.Password != "" {
		parts = append(parts, fmt.Sprintf("--auth %s", spec.Auth.Password))
	}

	if spec.TLS != nil {
		parts = append(parts, fmt.Sprintf("--tlsport %d", spec.TLS.Port))
		parts = append(parts, fmt.Sprintf("--tlscert %s/%s", tlsMountPath, tlsCertFile))
		parts = append(parts, fmt.Sprintf("--tlskey %s/%s", tlsMountPath, tlsKeyFile))
		parts = append(parts, fmt.Sprintf("--tlscacert %s/%s", tlsMountPath, tlsCACertFile))
	}

	if spec.ExtraFlags != "" {
		parts = append(parts, spec.ExtraFlags)
	}

	return strings.Join(parts, " ")
}

// applyDefaults fills in spec fields that have zero values with sensible defaults.
func applyDefaults(instance *cachev1alpha1.PogoCacheInstance) {
	if instance.Spec.Replicas == nil {
		instance.Spec.Replicas = int32Ptr(1)
	}
	if instance.Spec.Image == "" {
		instance.Spec.Image = "pogocache/pogocache:latest"
	}
	if instance.Spec.Port == 0 {
		instance.Spec.Port = 9401
	}
}

// pvcName returns the PVC name for a given instance.
func pvcName(instance *cachev1alpha1.PogoCacheInstance) string {
	return instance.Name + "-data"
}

// resourceLabels returns labels applied to all managed resources.
func resourceLabels(instance *cachev1alpha1.PogoCacheInstance) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "pogocache",
		"app.kubernetes.io/instance":   instance.Name,
		"app.kubernetes.io/managed-by": "pogocache-operator",
		"app.kubernetes.io/component":  "cache",
	}
}

// selectorLabels returns a stable subset of labels used for pod selection.
// These must not change after initial creation.
func selectorLabels(instance *cachev1alpha1.PogoCacheInstance) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "pogocache",
		"app.kubernetes.io/instance": instance.Name,
	}
}

// --- small helpers to obtain typed pointers ---

func int32Ptr(i int32) *int32 { return &i }
func int64Ptr(i int64) *int64 { return &i }
func boolPtr(b bool) *bool    { return &b }
