package e2e_encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"github.com/coreos/etcd/clientv3"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-openshift-apiserver-operator/pkg/operator/operatorclient"
	operatorencryption "github.com/openshift/cluster-openshift-apiserver-operator/test/library/encryption"
	"github.com/openshift/library-go/test/library/encryption"
)

func TestDecryptEtcdData(t *testing.T) {
	e := encryption.NewE(t)
	cs := encryption.GetClients(e)

	timeout, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// data
	encryptionKey64 := "Kt5ZWKBr0Nt7A0AIkTgwSGcsx4ShTYCqT81jeJZeMlU="                         // base64 encoded key taken from the encryption cfg in openshift-config-managed ns
	encryptionKeyID := "11"                                                                   // the name of the key taken from the encryption cfg in openshift-config-managed ns
	encryptionPrefix := "k8s:enc:aescbc:v1:"                                                  // encryption prefix that will be removed from encrypted data
	etcdKey := "/openshift.io/oauth/accesstokens/9N0JLFrw0Z9jqT8khAUZb2LyfQVObraaOoBdcX1rL7A" // a resource that will be retrieved from etcd

	// read the resource from etcd
	resp, err := cs.Etcd.Get(timeout, etcdKey, clientv3.WithPrefix())
	require.NoError(t, err)

	if len(resp.Kvs) != 1 {
		t.Fatalf("unexpected number of keys retruned from etcd, expected exactly one got %d", len(resp.Kvs))
	}

	// decode
	plain, err := decode(t, encryptionPrefix, encryptionKey64, encryptionKeyID, resp.Kvs[0].Value)
	require.NoError(t, err)
	fmt.Printf("decrypted data %s", plain)
}

func decode(t testing.TB, encryptionPrefix string, key64 string, keyID string, data []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(key64)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	prefixLen := len(encryptionPrefix) + len([]byte(keyID+":"))
	plainText, _, err := decryptAes(data[prefixLen:], block)
	return plainText, err
}

func decryptAes(data []byte, block cipher.Block) ([]byte, bool, error) {
	blockSize := aes.BlockSize
	if len(data) < blockSize {
		return nil, false, fmt.Errorf("the stored data was shorter than the required size")
	}
	iv := data[:blockSize]
	data = data[blockSize:]

	if len(data)%blockSize != 0 {
		return nil, false, fmt.Errorf("errInvalidBlockSize")
	}

	result := make([]byte, len(data))
	copy(result, data)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(result, result)

	// remove and verify PKCS#7 padding for CBC
	c := result[len(result)-1]
	paddingSize := int(c)
	size := len(result) - paddingSize
	if paddingSize == 0 || paddingSize > len(result) {
		return nil, false, fmt.Errorf("errInvalidPKCS7Data")
	}
	for i := 0; i < paddingSize; i++ {
		if result[size+i] != c {
			return nil, false, fmt.Errorf("errInvalidPKCS7Padding")
		}
	}

	return result[:size], false, nil
}

func TestEncryptionTypeIdentity(t *testing.T) {
	t.SkipNow()
	e := encryption.NewE(t)
	ns := operatorclient.GlobalMachineSpecifiedConfigNamespace
	labelSelector := "encryption.apiserver.operator.openshift.io/component" + "=" + operatorclient.TargetNamespace
	clientSet := encryption.SetAndWaitForEncryptionType(e, configv1.EncryptionTypeIdentity, operatorencryption.DefaultTargetGRs, ns, labelSelector)
	operatorencryption.AssertRoutesAndTokens(e, clientSet, configv1.EncryptionTypeIdentity, ns, labelSelector)
}

func TestEncryptionTypeUnset(t *testing.T) {
	t.SkipNow()
	e := encryption.NewE(t)
	ns := operatorclient.GlobalMachineSpecifiedConfigNamespace
	labelSelector := "encryption.apiserver.operator.openshift.io/component" + "=" + operatorclient.TargetNamespace
	clientSet := encryption.SetAndWaitForEncryptionType(e, "", operatorencryption.DefaultTargetGRs, ns, labelSelector)
	operatorencryption.AssertRoutesAndTokens(e, clientSet, configv1.EncryptionTypeIdentity, ns, labelSelector)
}

func TestEncryptionTurnOnAndOff(t *testing.T) {
	t.SkipNow()
	scenarios := []struct {
		name     string
		testFunc func(*testing.T)
	}{
		{name: "CreateAndStoreTokenOfLife", testFunc: func(t *testing.T) {
			e := encryption.NewE(t)
			operatorencryption.CreateAndStoreTokenOfLife(e, operatorencryption.GetClients(e))
		}},
		{name: "OnAESCBC", testFunc: operatorencryption.TestEncryptionTypeAESCBC},
		{name: "AssertTokenOfLifeEncrypted", testFunc: func(t *testing.T) {
			e := encryption.NewE(t)
			operatorencryption.AssertTokenOfLifeEncrypted(e, encryption.GetClients(e), operatorencryption.TokenOfLife(e))
		}},
		{name: "OffIdentity", testFunc: TestEncryptionTypeIdentity},
		{name: "AssertTokenOfLifeNotEncrypted", testFunc: func(t *testing.T) {
			e := encryption.NewE(t)
			operatorencryption.AssertTokenOfLifeNotEncrypted(e, encryption.GetClients(e), operatorencryption.TokenOfLife(e))
		}},
		{name: "OnAESCBCSecond", testFunc: operatorencryption.TestEncryptionTypeAESCBC},
		{name: "AssertTokenOfLifeEncryptedSecond", testFunc: func(t *testing.T) {
			e := encryption.NewE(t)
			operatorencryption.AssertTokenOfLifeEncrypted(e, encryption.GetClients(e), operatorencryption.TokenOfLife(e))
		}},
		{name: "OffIdentitySecond", testFunc: TestEncryptionTypeIdentity},
		{name: "AssertTokenOfLifeNotEncryptedSecond", testFunc: func(t *testing.T) {
			e := encryption.NewE(t)
			operatorencryption.AssertTokenOfLifeNotEncrypted(e, encryption.GetClients(e), operatorencryption.TokenOfLife(e))
		}},
	}

	// run scenarios
	for _, testScenario := range scenarios {
		t.Run(testScenario.name, testScenario.testFunc)
		if t.Failed() {
			t.Errorf("stopping the test as %q scenario failed", testScenario.name)
			return
		}
	}
}

// TestEncryptionRotation first encrypts data with aescbc key
// then it forces a key rotation by setting the "encyrption.Reason" in the operator's configuration file
func TestEncryptionRotation(t *testing.T) {
	t.SkipNow()
	// TODO: dump events, conditions in case of an failure for all scenarios

	// test data
	ns := operatorclient.GlobalMachineSpecifiedConfigNamespace
	labelSelector := "encryption.apiserver.operator.openshift.io/component" + "=" + operatorclient.TargetNamespace

	// step 1: create the secret of life
	e := encryption.NewE(t)
	clientSet := encryption.GetClients(e)
	operatorencryption.CreateAndStoreTokenOfLife(e, operatorencryption.GetClients(e))

	// step 2: run encryption aescbc scenario
	operatorencryption.TestEncryptionTypeAESCBC(t)

	// step 3: take samples
	rawEncryptedTokenOfLifeWithKey1 := operatorencryption.GetRawTokenOfLife(e, clientSet)

	// step 4: force key rotation and wait for migration to complete
	lastMigratedKeyMeta, err := encryption.GetLastKeyMeta(clientSet.Kube, ns, labelSelector)
	require.NoError(e, err)
	require.NoError(e, encryption.ForceKeyRotation(e, func(raw []byte) error {
		cs := operatorencryption.GetClients(t)
		apiServerOperator, err := cs.OperatorClient.Get("cluster", metav1.GetOptions{})
		if err != nil {
			return err
		}
		apiServerOperator.Spec.UnsupportedConfigOverrides.Raw = raw
		_, err = cs.OperatorClient.Update(apiServerOperator)
		return err
	}, fmt.Sprintf("test-key-rotation-%s", rand.String(4))))
	encryption.WaitForNextMigratedKey(e, clientSet.Kube, lastMigratedKeyMeta, operatorencryption.DefaultTargetGRs, ns, labelSelector)
	operatorencryption.AssertRoutesAndTokens(e, clientSet, configv1.EncryptionTypeAESCBC, ns, labelSelector)

	// step 5: verify if the secret of life was encrypted with a different key (step 2 vs step 4)
	rawEncryptedTokenOfLifeWithKey2 := operatorencryption.GetRawTokenOfLife(e, clientSet)
	if rawEncryptedTokenOfLifeWithKey1 == rawEncryptedTokenOfLifeWithKey2 {
		t.Errorf("expected the token of life to has a differnt content after a key rotation,\ncontentBeforeRotation %s\ncontentAfterRotation %s", rawEncryptedTokenOfLifeWithKey1, rawEncryptedTokenOfLifeWithKey2)
	}

	// TODO: assert conditions - operator and encryption migration controller must report status as active not progressing, and not failing for all scenarios
	// TODO: assert encryption config (resources) for all scenarios
}
