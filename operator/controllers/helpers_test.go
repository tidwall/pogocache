package controllers

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cachev1alpha1 "github.com/pogocache/pogocache/operator/api/v1alpha1"
)

// ---- helpers ----------------------------------------------------------------

func newInstance(name string) *cachev1alpha1.PogoCacheInstance {
	return &cachev1alpha1.PogoCacheInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       cachev1alpha1.PogoCacheInstanceSpec{},
	}
}

func int32p(v int32) *int32 { return &v }
func boolp(v bool) *bool    { return &v }

// ---- applyDefaults ----------------------------------------------------------

func TestApplyDefaults_SetsReplicas(t *testing.T) {
	inst := newInstance("x")
	applyDefaults(inst)
	if *inst.Spec.Replicas != 1 {
		t.Fatalf("want replicas=1, got %d", *inst.Spec.Replicas)
	}
}

func TestApplyDefaults_PreservesExistingReplicas(t *testing.T) {
	inst := newInstance("x")
	inst.Spec.Replicas = int32p(3)
	applyDefaults(inst)
	if *inst.Spec.Replicas != 3 {
		t.Fatalf("want replicas=3, got %d", *inst.Spec.Replicas)
	}
}

func TestApplyDefaults_SetsImage(t *testing.T) {
	inst := newInstance("x")
	applyDefaults(inst)
	const want = "pogocache/pogocache:latest"
	if inst.Spec.Image != want {
		t.Fatalf("want image=%q, got %q", want, inst.Spec.Image)
	}
}

func TestApplyDefaults_PreservesExistingImage(t *testing.T) {
	inst := newInstance("x")
	inst.Spec.Image = "myregistry/pogocache:v2"
	applyDefaults(inst)
	if inst.Spec.Image != "myregistry/pogocache:v2" {
		t.Fatalf("image should not change, got %q", inst.Spec.Image)
	}
}

func TestApplyDefaults_SetsPort(t *testing.T) {
	inst := newInstance("x")
	applyDefaults(inst)
	if inst.Spec.Port != 9401 {
		t.Fatalf("want port=9401, got %d", inst.Spec.Port)
	}
}

func TestApplyDefaults_PreservesExistingPort(t *testing.T) {
	inst := newInstance("x")
	inst.Spec.Port = 8080
	applyDefaults(inst)
	if inst.Spec.Port != 8080 {
		t.Fatalf("port should not change, got %d", inst.Spec.Port)
	}
}

// ---- pvcName ----------------------------------------------------------------

func TestPvcName(t *testing.T) {
	inst := newInstance("my-cache")
	if got := pvcName(inst); got != "my-cache-data" {
		t.Fatalf("want %q, got %q", "my-cache-data", got)
	}
}

// ---- resourceLabels / selectorLabels ----------------------------------------

func TestResourceLabels_ContainsRequiredKeys(t *testing.T) {
	inst := newInstance("my-cache")
	labels := resourceLabels(inst)

	required := []string{
		"app.kubernetes.io/name",
		"app.kubernetes.io/instance",
		"app.kubernetes.io/managed-by",
		"app.kubernetes.io/component",
	}
	for _, k := range required {
		if _, ok := labels[k]; !ok {
			t.Errorf("missing label key %q", k)
		}
	}
	if labels["app.kubernetes.io/instance"] != "my-cache" {
		t.Errorf("instance label mismatch, got %q", labels["app.kubernetes.io/instance"])
	}
}

func TestSelectorLabels_IsSubsetOfResourceLabels(t *testing.T) {
	inst := newInstance("my-cache")
	all := resourceLabels(inst)
	sel := selectorLabels(inst)

	for k, v := range sel {
		if all[k] != v {
			t.Errorf("selector label %q=%q not present in resource labels", k, v)
		}
	}
}

func TestSelectorLabels_IsStable(t *testing.T) {
	inst := newInstance("my-cache")
	a := selectorLabels(inst)
	b := selectorLabels(inst)
	for k := range a {
		if a[k] != b[k] {
			t.Errorf("selector labels not stable for key %q", k)
		}
	}
}

// ---- buildContainerPorts ----------------------------------------------------

func TestBuildContainerPorts_Default(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Port = 9401
	ports := buildContainerPorts(inst)
	if len(ports) != 1 {
		t.Fatalf("want 1 port, got %d", len(ports))
	}
	if ports[0].ContainerPort != 9401 {
		t.Errorf("want containerPort=9401, got %d", ports[0].ContainerPort)
	}
	if ports[0].Name != "pogocache" {
		t.Errorf("want name=pogocache, got %q", ports[0].Name)
	}
}

func TestBuildContainerPorts_WithTLS(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Port = 9401
	inst.Spec.TLS = &cachev1alpha1.TLSConfig{Port: 9402, SecretRef: "my-tls"}
	ports := buildContainerPorts(inst)
	if len(ports) != 2 {
		t.Fatalf("want 2 ports, got %d", len(ports))
	}
	if ports[1].Name != "tls" {
		t.Errorf("want second port name=tls, got %q", ports[1].Name)
	}
	if ports[1].ContainerPort != 9402 {
		t.Errorf("want tls port=9402, got %d", ports[1].ContainerPort)
	}
}

// ---- buildExtraFlags --------------------------------------------------------

func TestBuildExtraFlags_Empty(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Port = 9401 // default — should not appear in flags
	if got := buildExtraFlags(inst); got != "" {
		t.Errorf("want empty flags, got %q", got)
	}
}

func TestBuildExtraFlags_CustomPort(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Port = 8080
	assertFlag(t, buildExtraFlags(inst), "-p 8080")
}

func TestBuildExtraFlags_DefaultPortOmitted(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Port = 9401
	if strings.Contains(buildExtraFlags(inst), "-p ") {
		t.Error("default port 9401 should not produce a -p flag")
	}
}

func TestBuildExtraFlags_Threads(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Threads = int32p(8)
	assertFlag(t, buildExtraFlags(inst), "--threads 8")
}

func TestBuildExtraFlags_MaxMemory(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.MaxMemory = "512mb"
	assertFlag(t, buildExtraFlags(inst), "--maxmemory 512mb")
}

func TestBuildExtraFlags_EvictTrue(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Evict = boolp(true)
	assertFlag(t, buildExtraFlags(inst), "--evict yes")
}

func TestBuildExtraFlags_EvictFalse(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Evict = boolp(false)
	assertFlag(t, buildExtraFlags(inst), "--evict no")
}

func TestBuildExtraFlags_MaxConns(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.MaxConns = int32p(2048)
	assertFlag(t, buildExtraFlags(inst), "--maxconns 2048")
}

func TestBuildExtraFlags_Persist(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Persist = &cachev1alpha1.PersistConfig{
		Path: "/data/pogocache.db",
		Size: resource.MustParse("1Gi"),
	}
	assertFlag(t, buildExtraFlags(inst), "--persist /data/pogocache.db")
}

func TestBuildExtraFlags_AuthLiteralPassword(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Auth = &cachev1alpha1.AuthConfig{Password: "s3cr3t"}
	assertFlag(t, buildExtraFlags(inst), "--auth s3cr3t")
}

func TestBuildExtraFlags_AuthSecretRef_NoAuthFlag(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Auth = &cachev1alpha1.AuthConfig{
		SecretRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
			Key:                  "password",
		},
	}
	flags := buildExtraFlags(inst)
	if strings.Contains(flags, "--auth") {
		t.Errorf("SecretRef auth must not emit --auth in flags, got %q", flags)
	}
}

func TestBuildExtraFlags_TLS(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.TLS = &cachev1alpha1.TLSConfig{Port: 9402, SecretRef: "my-tls"}
	flags := buildExtraFlags(inst)
	assertFlag(t, flags, "--tlsport 9402")
	assertFlag(t, flags, "--tlscert /etc/pogocache/tls/tls.crt")
	assertFlag(t, flags, "--tlskey /etc/pogocache/tls/tls.key")
	assertFlag(t, flags, "--tlscacert /etc/pogocache/tls/ca.crt")
}

func TestBuildExtraFlags_ExtraFlags(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.ExtraFlags = "--reuseport yes"
	assertFlag(t, buildExtraFlags(inst), "--reuseport yes")
}

func TestBuildExtraFlags_Combined(t *testing.T) {
	inst := newInstance("c")
	inst.Spec.Port = 9401 // default, omitted
	inst.Spec.Threads = int32p(4)
	inst.Spec.MaxMemory = "1gb"
	inst.Spec.Evict = boolp(true)
	inst.Spec.MaxConns = int32p(1024)
	inst.Spec.Persist = &cachev1alpha1.PersistConfig{
		Path: "/data/cache.db",
		Size: resource.MustParse("2Gi"),
	}

	flags := buildExtraFlags(inst)
	for _, want := range []string{
		"--threads 4",
		"--maxmemory 1gb",
		"--evict yes",
		"--maxconns 1024",
		"--persist /data/cache.db",
	} {
		assertFlag(t, flags, want)
	}
	if strings.Contains(flags, "-p ") {
		t.Error("default port should not appear in combined flags")
	}
}

// ---- buildPodSpec -----------------------------------------------------------

func TestBuildPodSpec_NoPersistNoVolumes(t *testing.T) {
	inst := newInstance("c")
	applyDefaults(inst)
	r := &PogoCacheInstanceReconciler{}
	pod := r.buildPodSpec(inst)
	for _, v := range pod.Volumes {
		if v.Name == "data" {
			t.Error("no data volume expected without persist config")
		}
	}
}

func TestBuildPodSpec_PersistAddsDataVolume(t *testing.T) {
	inst := newInstance("c")
	applyDefaults(inst)
	inst.Spec.Persist = &cachev1alpha1.PersistConfig{
		Path: "/data/cache.db",
		Size: resource.MustParse("1Gi"),
	}
	r := &PogoCacheInstanceReconciler{}
	pod := r.buildPodSpec(inst)

	found := false
	for _, v := range pod.Volumes {
		if v.Name == "data" {
			found = true
			if v.PersistentVolumeClaim == nil {
				t.Error("data volume should use PVC source")
			}
		}
	}
	if !found {
		t.Error("data volume not found")
	}

	foundMount := false
	for _, m := range pod.Containers[0].VolumeMounts {
		if m.Name == "data" && m.MountPath == dataMountPath {
			foundMount = true
		}
	}
	if !foundMount {
		t.Errorf("data volume mount at %q not found", dataMountPath)
	}
}

func TestBuildPodSpec_TLSAddsTLSVolume(t *testing.T) {
	inst := newInstance("c")
	applyDefaults(inst)
	inst.Spec.TLS = &cachev1alpha1.TLSConfig{Port: 9402, SecretRef: "my-tls"}
	r := &PogoCacheInstanceReconciler{}
	pod := r.buildPodSpec(inst)

	found := false
	for _, v := range pod.Volumes {
		if v.Name == "tls" {
			found = true
			if v.Secret == nil || v.Secret.SecretName != "my-tls" {
				t.Errorf("tls volume should reference secret %q", "my-tls")
			}
		}
	}
	if !found {
		t.Error("tls volume not found")
	}

	foundMount := false
	for _, m := range pod.Containers[0].VolumeMounts {
		if m.Name == "tls" && m.MountPath == tlsMountPath && m.ReadOnly {
			foundMount = true
		}
	}
	if !foundMount {
		t.Errorf("tls volume mount at %q (readonly) not found", tlsMountPath)
	}
}

func TestBuildPodSpec_AuthSecretRefInjectsEnvVar(t *testing.T) {
	inst := newInstance("c")
	applyDefaults(inst)
	inst.Spec.Auth = &cachev1alpha1.AuthConfig{
		SecretRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "auth-secret"},
			Key:                  "password",
		},
	}
	r := &PogoCacheInstanceReconciler{}
	pod := r.buildPodSpec(inst)

	found := false
	for _, e := range pod.Containers[0].Env {
		if e.Name == "POGOCACHE_AUTH_PASSWORD" {
			found = true
			if e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
				t.Error("POGOCACHE_AUTH_PASSWORD must come from SecretKeyRef")
			}
		}
	}
	if !found {
		t.Error("POGOCACHE_AUTH_PASSWORD env var not found")
	}
}

func TestBuildPodSpec_RunsAsNonRoot(t *testing.T) {
	inst := newInstance("c")
	applyDefaults(inst)
	r := &PogoCacheInstanceReconciler{}
	pod := r.buildPodSpec(inst)

	sc := pod.SecurityContext
	if sc == nil {
		t.Fatal("pod security context must be set")
	}
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Error("RunAsNonRoot must be true")
	}
}

func TestBuildPodSpec_ExtraFlagsEnvVar(t *testing.T) {
	inst := newInstance("c")
	applyDefaults(inst)
	inst.Spec.Threads = int32p(4)
	r := &PogoCacheInstanceReconciler{}
	pod := r.buildPodSpec(inst)

	for _, e := range pod.Containers[0].Env {
		if e.Name == "POGOCACHE_EXTRA_FLAGS" {
			if !strings.Contains(e.Value, "--threads 4") {
				t.Errorf("POGOCACHE_EXTRA_FLAGS missing --threads 4, got %q", e.Value)
			}
			return
		}
	}
	t.Error("POGOCACHE_EXTRA_FLAGS env var not found")
}

// ---- assertFlag helper ------------------------------------------------------

// assertFlag fails the test if substr is not found in flags.
func assertFlag(t *testing.T, flags, substr string) {
	t.Helper()
	if !strings.Contains(flags, substr) {
		t.Errorf("flags %q does not contain %q", flags, substr)
	}
}
