package encryption

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1 "github.com/openshift/api/config/v1"
	oauthapiv1 "github.com/openshift/api/oauth/v1"
	library "github.com/openshift/library-go/test/library/encryption"
)

var DefaultTargetGRs = []schema.GroupResource{
	{Group: "route.openshift.io", Resource: "routes"},
	{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
	{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
}

func AssertTokenOfLifeEncrypted(t testing.TB, clientSet library.ClientSet, tokenOfLife *oauthapiv1.OAuthAccessToken) {
	t.Helper()
	rawTokenValue := GetRawTokenOfLife(t, clientSet)
	if strings.Contains(rawTokenValue, tokenOfLife.RefreshToken) {
		t.Errorf("access token not encrypted, token received from etcd have %q (plain text), raw content in etcd is %s", tokenOfLife.RefreshToken, rawTokenValue)
	}
}

func AssertTokenOfLifeNotEncrypted(t testing.TB, clientSet library.ClientSet, tokenOfLife *oauthapiv1.OAuthAccessToken) {
	t.Helper()
	rawTokenValue := GetRawTokenOfLife(t, clientSet)
	if !strings.Contains(rawTokenValue, tokenOfLife.RefreshToken) {
		t.Errorf("access token received from etcd doesnt have %q (plain text), raw content in etcd is %s", tokenOfLife.RefreshToken, rawTokenValue)
	}
}

func AssertRoutesAndTokens(t testing.TB, clientSet library.ClientSet, expectedMode configv1.EncryptionType, namespace, labelSelector string) {
	t.Helper()
	assertRoutes(t, clientSet.Etcd, string(expectedMode))
	assertAccessTokens(t, clientSet.Etcd, string(expectedMode))
	assertAuthTokens(t, clientSet.Etcd, string(expectedMode))
	library.AssertLastMigratedKey(t, clientSet.Kube, DefaultTargetGRs, namespace, labelSelector)
}

func assertRoutes(t testing.TB, etcdClient library.EtcdClient, expectedMode string) {
	t.Logf("Checking if all Routes where encrypted/decrypted for %q mode", expectedMode)
	totalRoutes, err := library.VerifyResources(t, etcdClient, "/openshift.io/routes/", expectedMode, false)
	t.Logf("Verified %d Routes, err %v", totalRoutes, err)
	require.NoError(t, err)
}

func assertAccessTokens(t testing.TB, etcdClient library.EtcdClient, expectedMode string) {
	t.Logf("Checking if all OauthAccessTokens where encrypted/decrypted for %q mode", expectedMode)
	totalAccessTokens, err := library.VerifyResources(t, etcdClient, "/openshift.io/oauth/accesstokens/", expectedMode, true)
	t.Logf("Verified %d OauthAccessTokens, err %v", totalAccessTokens, err)
	require.NoError(t, err)
}

func assertAuthTokens(t testing.TB, etcdClient library.EtcdClient, expectedMode string) {
	t.Logf("Checking if all OAuthAuthorizeTokens where encrypted/decrypted for %q mode", expectedMode)
	totalAuthTokens, err := library.VerifyResources(t, etcdClient, "/openshift.io/oauth/authorizetokens/", expectedMode, true)
	t.Logf("Verified %d OAuthAuthorizeTokens, err %v", totalAuthTokens, err)
	require.NoError(t, err)
}
