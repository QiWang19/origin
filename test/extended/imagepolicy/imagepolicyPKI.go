package imagepolicy

import (
	"context"
	"path/filepath"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	admissionapi "k8s.io/pod-security-admission/api"
)

var _ = g.Describe("[sig-imagepolicy][OCPFeatureGate:SigstoreImageVerificationPKI][Serial]", g.Ordered, func() {
	defer g.GinkgoRecover()
	var (
		oc                           = exutil.NewCLIWithoutNamespace("cluster-image-policy")
		tctx                         = context.Background()
		cli                          = exutil.NewCLIWithPodSecurityLevel("verifysigstore-e2e", admissionapi.LevelBaseline)
		clif                         = cli.KubeFramework()
		imgpolicyCli                 = exutil.NewCLIWithPodSecurityLevel("verifysigstore-imagepolicy-e2e", admissionapi.LevelBaseline)
		imgpolicyClif                = imgpolicyCli.KubeFramework()
		imagePolicyBaseDir           = exutil.FixturePath("testdata", "imagepolicy")
		pkiClusterImagePolicyFixture = filepath.Join(imagePolicyBaseDir, "pki-cluster-image-policy.yaml")
		invalidPKIImagePolicyFixture = filepath.Join(imagePolicyBaseDir, "invalid-pki-image-policy.yaml")
		pkiImagePolicyFixture        = filepath.Join(imagePolicyBaseDir, "pki-image-policy.yaml")
	)

	g.It("Should fail clusterimagepolicy signature validation root of trust the PKI signature does not exist", func() {
		createClusterImagePolicy(oc, pkiClusterImagePolicyFixture)

		waitForPoolComplete(oc)

		pod, err := launchTestPod(tctx, clif, testPodName, testReleaseImageScope)
		o.Expect(err).NotTo(o.HaveOccurred())
		g.DeferCleanup(deleteTestPod, tctx, clif, testPodName)

		err = waitForTestPodContainerToFailSignatureValidation(tctx, clif, pod)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("Should pass clusterimagepolicy PKI signature validation with signed image", func() {
		pod, err := launchTestPod(tctx, clif, testPodName, testPKISignedImageScopeBusybox)
		o.Expect(err).NotTo(o.HaveOccurred())
		g.DeferCleanup(deleteTestPod, tctx, clif, testPodName)

		err = e2epod.WaitForPodSuccessInNamespace(tctx, clif.ClientSet, pod.Name, pod.Namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("Should fail imagepolicy PKI signature validation root of trust does not match the identity in the signature", func() {
		createImagePolicy(oc, invalidPKIImagePolicyFixture, imgpolicyClif.Namespace.Name)
		// g.DeferCleanup(deleteClusterImagePolicy, oc, pkiClusterImagePolicyFixture)
		g.DeferCleanup(deleteImagePolicy, oc, invalidPKIImagePolicyFixture, imgpolicyClif.Namespace.Name)

		waitForPoolComplete(oc)

		pod, err := launchTestPod(tctx, imgpolicyClif, testPodName, testReferenceImageScope)
		o.Expect(err).NotTo(o.HaveOccurred())
		g.DeferCleanup(deleteTestPod, tctx, imgpolicyClif, testPodName)

		err = waitForTestPodContainerToFailSignatureValidation(tctx, imgpolicyClif, pod)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("Should pass imagepolicy PKI signature validation with signed image", func() {
		createImagePolicy(oc, pkiImagePolicyFixture, imgpolicyClif.Namespace.Name)
		// g.DeferCleanup(deleteImagePolicy, oc, pkiImagePolicyFixture, imgpolicyClif.Namespace.Name)

		waitForPoolComplete(oc)

		pod, err := launchTestPod(tctx, imgpolicyClif, testPodName, testPKISignedImageScopeBYO)
		o.Expect(err).NotTo(o.HaveOccurred())
		// g.DeferCleanup(deleteTestPod, tctx, imgpolicyClif, testPodName)

		err = e2epod.WaitForPodSuccessInNamespace(tctx, imgpolicyClif.ClientSet, pod.Name, pod.Namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	// g.AfterAll(func() {
	// 	//cleanup ClusterImagePolicy resources
	// 	err := deleteClusterImagePolicy(oc, pkiClusterImagePolicyFixture)
	// 	o.Expect(err).NotTo(o.HaveOccurred())
	// })

})
