package client

import (
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"

	dockerTlsConfig "github.com/docker/docker/pkg/tlsconfig"
	"github.com/docker/go-connections/sockets"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/stretchr/testify/require"
)

const (
	rsaEncryptedPrivateKeyFile    = "testdata/key.pem"
	certificateOfEncryptedKeyFile = "testdata/cert.pem"
	caOfEncryptedKeyFile          = "testdata/ca.pem"
)

func getCertAndEncryptedKey() (string, string, string) {
	return rsaEncryptedPrivateKeyFile, certificateOfEncryptedKeyFile, caOfEncryptedKeyFile
}

func TestCloseWrite(t *testing.T) {

	key, cert, ca := getCertAndEncryptedKey()
	tlsConfig, err := tlsconfig.Client(tlsconfig.Options{
		CertFile:           cert, //cert_of_encrypted
		KeyFile:            key,  //enctyted_pem
		InsecureSkipVerify: os.Getenv("DOCKER_TLS_VERIFY") == "",
		CAFile:             ca,
	})

	require.NoError(t, err, "Unable to configure TLS Config")

	dialer := net.Dialer{}

	proxyDialer, err := sockets.DialerFromEnvironment(&dialer)
	require.NoError(t, err, "Unable to create Dialer")

	ln, err := tls.Listen("tcp", ":8080", tlsConfig)
	require.NoError(t, err, "Unable to listen to server")
	defer ln.Close()

	address := "127.0.0.1:8080"
	rawConn, err := proxyDialer.Dial("tcp", address)
	require.NoError(t, err, "Unable to create Raw Connection")

	colonPos := strings.LastIndex(address, ":")
	if colonPos == -1 {
		colonPos = len(address)
	}
	hostname := address[:colonPos]
	config := dockerTlsConfig.Clone(tlsConfig)
	config.ServerName = hostname

	conn := tls.Client(rawConn, config)
	newStruct := &tlsClientCon{conn, rawConn}

	closingError := newStruct.CloseWrite()
	require.Nil(t, closingError, "Unable to Close write the connection.")
}
