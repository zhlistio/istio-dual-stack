// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"go.uber.org/atomic"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/nodeagent/caclient"
	"istio.io/pkg/log"
)

const (
	bearerTokenPrefix = "Bearer "
)

var citadelClientLog = log.RegisterScope("citadelclient", "citadel client debugging", 0)

type CitadelClient struct {
	enableTLS     bool
	caTLSRootCert []byte
	client        pb.IstioCertificateServiceClient
	conn          *grpc.ClientConn
	provider      *caclient.TokenProvider
	opts          *security.Options
	usingMtls     *atomic.Bool
}

// NewCitadelClient create a CA client for Citadel.
// NewCitadelClient 为 Citadel 创建 CA 客户端。
func NewCitadelClient(opts *security.Options, tls bool, rootCert []byte) (*CitadelClient, error) {
	c := &CitadelClient{
		enableTLS:     tls,
		caTLSRootCert: rootCert,
		opts:          opts,
		provider:      caclient.NewCATokenProvider(opts),
		usingMtls:     atomic.NewBool(false),
	}

	conn, err := c.buildConnection()
	if err != nil {
		citadelClientLog.Errorf("Failed to connect to endpoint %s: %v", opts.CAEndpoint, err)
		return nil, fmt.Errorf("failed to connect to endpoint %s", opts.CAEndpoint)
	}
	c.conn = conn
	c.client = pb.NewIstioCertificateServiceClient(conn)
	return c, nil
}

func (c *CitadelClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// CSR Sign calls Citadel to sign a CSR.
func (c *CitadelClient) CSRSign(csrPEM []byte, certValidTTLInSec int64) ([]string, error) {
	req := &pb.IstioCertificateRequest{
		Csr:              string(csrPEM),
		ValidityDuration: certValidTTLInSec,
	}
	if err := c.reconnectIfNeeded(); err != nil {
		return nil, err
	}
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	resp, err := c.client.CreateCertificate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %v", err)
	}

	if len(resp.CertChain) <= 1 {
		return nil, errors.New("invalid empty CertChain")
	}

	return resp.CertChain, nil
}

func (c *CitadelClient) getTLSDialOption() (grpc.DialOption, error) {
	// Load the TLS root certificate from the specified file.
	// Create a certificate pool
	var certPool *x509.CertPool
	var err error
	if c.caTLSRootCert == nil {
		// No explicit certificate - assume the citadel-compatible server uses a public cert
		certPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		citadelClientLog.Info("Citadel client using public DNS: ", c.opts.CAEndpoint)
	} else {
		certPool = x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(c.caTLSRootCert)
		if !ok {
			return nil, fmt.Errorf("failed to append certificates")
		}
		citadelClientLog.Info("Citadel client using custom root cert: ", c.opts.CAEndpoint)
		/**
		2021-06-01T03:00:04.995849Z	info	citadelclient	Citadel client using custom root: istiod-iop-1-8-4.istio-system.svc:15012 -----BEGIN CERTIFICATE-----
		MIIFCTCCAvGgAwIBAgIJAP/LfI/QveTRMA0GCSqGSIb3DQEBCwUAMCIxDjAMBgNV
		BAoMBUlzdGlvMRAwDgYDVQQDDAdSb290IENBMB4XDTIwMDcwMjAyNDA1NloXDTMw
		MDYzMDAyNDA1NlowIjEOMAwGA1UECgwFSXN0aW8xEDAOBgNVBAMMB1Jvb3QgQ0Ew
		ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDMhz3bVBc8K35sp9H/OtVt
		hkvnfRU6LLi2eVKOUilGBM7GXelFEDA70prSqnzt3o01ldRx76WrR+w/RndAEVoT
		rAgLJAQ77JaFa/XVxvnQq/iOvMm6KpzZaUmowP4Hx7EFaTmnEPgfOGz9nodLQf7A
		2Irp8HtzgAT5X9d/yYCc3vUPOpXPRXa+RWE0vRgY0sqjNjcbIoZ0/fQN71NuSD2y
		nNYI2fUyUsKNfdpuOpYg+PqZCsFGXu6ARhxuVKM0RAGRNCZ6YqklhgP2bJuGGCfp
		BYirryT49Hv7yClAF8R8j8ueq7pQ/RLEpTi1J5bripVEaP3fA/bKXa1KIv1NHGOl
		3FYyUBTPudeOu2h/J7RVbb3pnqHddqnFD1pchL5F3gwC/8wz+6FnqgLkvJwTJw0T
		jHWsExPsB8O0myTGGGM70o0el7/UWNl53Xj3U51cSWJ4vU8ngIw7HW4MYyg5IBzR
		v5LuVVQViF4fygIJiHHzIQnAa5H8Gd6qDY/m/tqwJgjVHOLyvoT18Y9+MU67eV9u
		j6qNrnai2DSSxqlwSSnea9nvruik9ymX1QYlifnnxF8B2Vp40msMXjnch6Ks81Rw
		pDPb8p0xO/4LWZv5/FbyOq7skRgV9uN+GtJvU4bELw6XLGRP50EXvd9rJdsLBmex
		OTUg+eiIeQsRQQich4aI/wIDAQABo0IwQDAdBgNVHQ4EFgQU5qpAqx8bjyFfgfso
		FeJq4GuYN48wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAuQwDQYJKoZI
		hvcNAQELBQADggIBADpPSyQ8JzNnOtSp1hitColXp92sHRp+iNb+VnEGSfuPdy1u
		SurS3QwWevZX0JohvDM5z/WHhOBLFnnlklGYSTTf7PtzKg5i8JRrmLH3dpW/nA9S
		fwnkaK1YatLduaNMX1cC2jsg47wSk451T6hcySshtONiFjpFpAGT/mMJ563k2tpc
		60M1aVEl2fwGar97MaI1dfdUVl337MimFL37epINPS8+ympDpPL9SVvr22hZBWVD
		5V6btLFU3nZ3dZT5+KBE2xJAoox3DgnvJURdecPg5SMVUvjOdX3Ok5MtZLsda99J
		r/J+XKFLTnZU7y+QI26dzBHcfCMPJO4mT8i7ymfywRmJqQH/n5Nq6TK7itLfBUpB
		m5sDb3rkkG9GSd4du4uKr/HGyaBw7owG2raj02TsTksPy0kn1yQm5tgRXpYeT5Mv
		2gFrsVRNwOlNkkGpdVCidwn1Z518uu5J/DOsQwe3+7Z0r18fc0H8d7Y5fyYLUCJ8
		c7qli2G4WP+LILpR/uB/o+wZjJJHEII22dHBvGu0a1v8ZBRVtvq96hO63YI8JI5T
		VZBtyVBVRzyyW4y8lokM+OHcIQ57y8pCTGmmzQcXrxlrDvyS/3br68Suk4H14e6A
		Y255A4VfgZd3Wv57OhA97i9+pGwT5Va+BDoX5T8mneUxJm4dMBtEvQoeui5E
		-----END CERTIFICATE-----
		*/
	}
	var certificate tls.Certificate
	config := tls.Config{
		Certificates: []tls.Certificate{certificate},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if c.opts.ProvCert != "" {
				// Load the certificate from disk
				certificate, err = tls.LoadX509KeyPair(
					filepath.Join(c.opts.ProvCert, "cert-chain.pem"),
					filepath.Join(c.opts.ProvCert, "key.pem"))
				if err != nil {
					// we will return an empty cert so that when user sets the Prov cert path
					// but not have such cert in the file path we use the token to provide verification
					// instead of just broken the workflow
					citadelClientLog.Warnf("cannot load key pair, using token instead: %v", err)
					return &certificate, nil
				}
				c.usingMtls.Store(true)
			}
			return &certificate, nil
		},
	}
	config.RootCAs = certPool

	// For debugging on localhost (with port forward)
	// TODO: remove once istiod is stable and we have a way to validate JWTs locally
	if strings.Contains(c.opts.CAEndpoint, "localhost") {
		config.ServerName = "istiod.istio-system.svc"
	}

	transportCreds := credentials.NewTLS(&config)
	return grpc.WithTransportCredentials(transportCreds), nil
}

func (c *CitadelClient) buildConnection() (*grpc.ClientConn, error) {
	var opts grpc.DialOption
	var err error
	if c.enableTLS {
		opts, err = c.getTLSDialOption()
		if err != nil {
			return nil, err
		}
	} else {
		opts = grpc.WithInsecure()
	}

	conn, err := grpc.Dial(c.opts.CAEndpoint,
		opts,
		grpc.WithPerRPCCredentials(c.provider),
		security.CARetryInterceptor())
	if err != nil {
		citadelClientLog.Errorf("Failed to connect to endpoint %s: %v", c.opts.CAEndpoint, err)
		return nil, fmt.Errorf("failed to connect to endpoint %s", c.opts.CAEndpoint)
	}

	return conn, nil
}

func (c *CitadelClient) reconnectIfNeeded() error {
	if c.opts.ProvCert == "" || c.usingMtls.Load() {
		// No need to reconnect, already using mTLS or never will use it
		return nil
	}
	_, err := tls.LoadX509KeyPair(
		filepath.Join(c.opts.ProvCert, "cert-chain.pem"),
		filepath.Join(c.opts.ProvCert, "key.pem"))
	if err != nil {
		// Cannot load the certificates yet, don't both reconnecting
		return nil
	}

	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("failed to close connection")
	}

	conn, err := c.buildConnection()
	if err != nil {
		return err
	}
	c.conn = conn
	c.client = pb.NewIstioCertificateServiceClient(conn)
	citadelClientLog.Errorf("recreated connection")
	return nil
}
