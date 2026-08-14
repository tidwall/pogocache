package controllers

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cachev1alpha1 "github.com/pogocache/pogocache/operator/api/v1alpha1"
)

// ---- scheme & reconciler factory --------------------------------------------

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(appsv1.AddToScheme(s))
	utilruntime.Must(corev1.AddToScheme(s))
	utilruntime.Must(cachev1alpha1.AddToScheme(s))
	return s
}

func newTestReconciler(scheme *runtime.Scheme, objs ...runtime.Object) *PogoCacheInstanceReconciler {
	runtimeObjs := make([]runtime.Object, len(objs))
	copy(runtimeObjs, objs)

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(runtimeObjs...).
		WithStatusSubresource(&cachev1alpha1.PogoCacheInstance{}).
		Build()

	return &PogoCacheInstanceReconciler{Client: cl, Scheme: scheme}
}

// reconcileTwice runs Reconcile twice: the first pass adds the finalizer and
// requeues; the second pass performs the actual resource creation.
func reconcileTwice(t *testing.T, r *PogoCacheInstanceReconciler, key types.NamespacedName) {
	t.Helper()
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: key}

	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile pass %d: %v", i+1, err)
		}
	}
}

// ---- Deployment -------------------------------------------------------------

func TestReconcile_CreatesDeployment(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	r := newTestReconciler(scheme, inst)

	key := types.NamespacedName{Name: inst.Name, Namespace: inst.Namespace}
	reconcileTwice(t, r, key)

	dep := &appsv1.Deployment{}
	if err := r.Get(context.Background(), key, dep); err != nil {
		t.Fatalf("Deployment not created: %v", err)
	}
}

func TestReconcile_Deployment_Replicas(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	inst.Spec.Replicas = int32p(3)
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	dep := &appsv1.Deployment{}
	_ = r.Get(context.Background(), namespacedKey(inst), dep)
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 3 {
		t.Errorf("want replicas=3, got %v", dep.Spec.Replicas)
	}
}

func TestReconcile_Deployment_Image(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	inst.Spec.Image = "myregistry/pogocache:v1.2.3"
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	dep := &appsv1.Deployment{}
	_ = r.Get(context.Background(), namespacedKey(inst), dep)
	if got := dep.Spec.Template.Spec.Containers[0].Image; got != "myregistry/pogocache:v1.2.3" {
		t.Errorf("want image=%q, got %q", "myregistry/pogocache:v1.2.3", got)
	}
}

func TestReconcile_Deployment_DefaultImage(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	dep := &appsv1.Deployment{}
	_ = r.Get(context.Background(), namespacedKey(inst), dep)
	const want = "pogocache/pogocache:latest"
	if got := dep.Spec.Template.Spec.Containers[0].Image; got != want {
		t.Errorf("want default image=%q, got %q", want, got)
	}
}

func TestReconcile_Deployment_SelectorLabels(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	dep := &appsv1.Deployment{}
	_ = r.Get(context.Background(), namespacedKey(inst), dep)

	sel := dep.Spec.Selector.MatchLabels
	if sel["app.kubernetes.io/name"] != "pogocache" {
		t.Errorf("selector missing expected label, got %v", sel)
	}
	if sel["app.kubernetes.io/instance"] != inst.Name {
		t.Errorf("selector instance label mismatch, got %v", sel)
	}
}

func TestReconcile_Deployment_OwnerReference(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	dep := &appsv1.Deployment{}
	_ = r.Get(context.Background(), namespacedKey(inst), dep)

	if len(dep.OwnerReferences) == 0 {
		t.Fatal("Deployment must have an owner reference pointing to the PogoCacheInstance")
	}
	if dep.OwnerReferences[0].Name != inst.Name {
		t.Errorf("owner reference name mismatch: got %q", dep.OwnerReferences[0].Name)
	}
}

// ---- Service ----------------------------------------------------------------

func TestReconcile_CreatesService(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	svc := &corev1.Service{}
	if err := r.Get(context.Background(), namespacedKey(inst), svc); err != nil {
		t.Fatalf("Service not created: %v", err)
	}
}

func TestReconcile_Service_DefaultPort(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	svc := &corev1.Service{}
	_ = r.Get(context.Background(), namespacedKey(inst), svc)

	if len(svc.Spec.Ports) != 1 {
		t.Fatalf("want 1 service port, got %d", len(svc.Spec.Ports))
	}
	if svc.Spec.Ports[0].Port != 9401 {
		t.Errorf("want port=9401, got %d", svc.Spec.Ports[0].Port)
	}
	if svc.Spec.Ports[0].Name != "pogocache" {
		t.Errorf("want port name=pogocache, got %q", svc.Spec.Ports[0].Name)
	}
}

func TestReconcile_Service_TLSAddsPort(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	inst.Spec.TLS = &cachev1alpha1.TLSConfig{Port: 9402, SecretRef: "my-tls"}
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	svc := &corev1.Service{}
	_ = r.Get(context.Background(), namespacedKey(inst), svc)

	if len(svc.Spec.Ports) != 2 {
		t.Fatalf("want 2 service ports with TLS, got %d", len(svc.Spec.Ports))
	}
	if svc.Spec.Ports[1].Name != "tls" {
		t.Errorf("want second port name=tls, got %q", svc.Spec.Ports[1].Name)
	}
	if svc.Spec.Ports[1].Port != 9402 {
		t.Errorf("want TLS port=9402, got %d", svc.Spec.Ports[1].Port)
	}
}

func TestReconcile_Service_ClusterIP(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	svc := &corev1.Service{}
	_ = r.Get(context.Background(), namespacedKey(inst), svc)

	if svc.Spec.Type != "" && svc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("want ClusterIP service, got %q", svc.Spec.Type)
	}
}

func TestReconcile_Service_SelectorMatchesPods(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	svc := &corev1.Service{}
	_ = r.Get(context.Background(), namespacedKey(inst), svc)
	dep := &appsv1.Deployment{}
	_ = r.Get(context.Background(), namespacedKey(inst), dep)

	// The service selector must match every label in the deployment pod template.
	for k, v := range svc.Spec.Selector {
		if dep.Spec.Template.Labels[k] != v {
			t.Errorf("service selector %q=%q not present in pod template labels", k, v)
		}
	}
}

// ---- PersistentVolumeClaim --------------------------------------------------

func TestReconcile_NoPVC_WhenPersistNil(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	pvc := &corev1.PersistentVolumeClaim{}
	err := r.Get(context.Background(), types.NamespacedName{
		Name:      pvcName(inst),
		Namespace: inst.Namespace,
	}, pvc)
	if err == nil {
		t.Error("PVC must not be created when persist is not configured")
	}
}

func TestReconcile_CreatesPVC_WhenPersistSet(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	inst.Spec.Persist = &cachev1alpha1.PersistConfig{
		Path: "/data/cache.db",
		Size: resource.MustParse("2Gi"),
	}
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	pvc := &corev1.PersistentVolumeClaim{}
	if err := r.Get(context.Background(), types.NamespacedName{
		Name:      pvcName(inst),
		Namespace: inst.Namespace,
	}, pvc); err != nil {
		t.Fatalf("PVC not created: %v", err)
	}
}

func TestReconcile_PVC_StorageSize(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	inst.Spec.Persist = &cachev1alpha1.PersistConfig{
		Path: "/data/cache.db",
		Size: resource.MustParse("5Gi"),
	}
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	pvc := &corev1.PersistentVolumeClaim{}
	_ = r.Get(context.Background(), types.NamespacedName{
		Name:      pvcName(inst),
		Namespace: inst.Namespace,
	}, pvc)

	got := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	want := resource.MustParse("5Gi")
	if got.Cmp(want) != 0 {
		t.Errorf("PVC size: want %v, got %v", want.String(), got.String())
	}
}

func TestReconcile_PVC_OwnerReference(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	inst.Spec.Persist = &cachev1alpha1.PersistConfig{
		Path: "/data/cache.db",
		Size: resource.MustParse("1Gi"),
	}
	r := newTestReconciler(scheme, inst)

	reconcileTwice(t, r, namespacedKey(inst))

	pvc := &corev1.PersistentVolumeClaim{}
	_ = r.Get(context.Background(), types.NamespacedName{
		Name:      pvcName(inst),
		Namespace: inst.Namespace,
	}, pvc)

	if len(pvc.OwnerReferences) == 0 {
		t.Fatal("PVC must have owner reference")
	}
	if pvc.OwnerReferences[0].Name != inst.Name {
		t.Errorf("owner reference name mismatch: got %q", pvc.OwnerReferences[0].Name)
	}
}

// ---- Finalizer --------------------------------------------------------------

func TestReconcile_AddsFinalizer(t *testing.T) {
	scheme := newTestScheme()
	inst := minimalInstance("test-cache")
	r := newTestReconciler(scheme, inst)

	ctx := context.Background()
	req := ctrl.Request{NamespacedName: namespacedKey(inst)}

	// First reconcile only adds the finalizer.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	updated := &cachev1alpha1.PogoCacheInstance{}
	_ = r.Get(ctx, namespacedKey(inst), updated)

	found := false
	for _, f := range updated.Finalizers {
		if f == finalizerName {
			found = true
		}
	}
	if !found {
		t.Errorf("finalizer %q not added after first reconcile", finalizerName)
	}
}

// ---- test helpers -----------------------------------------------------------

func minimalInstance(name string) *cachev1alpha1.PogoCacheInstance {
	return &cachev1alpha1.PogoCacheInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: cachev1alpha1.PogoCacheInstanceSpec{},
	}
}

func namespacedKey(inst *cachev1alpha1.PogoCacheInstance) types.NamespacedName {
	return types.NamespacedName{Name: inst.Name, Namespace: inst.Namespace}
}
