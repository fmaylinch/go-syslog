package syslog

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	. "gopkg.in/check.v1"
)

func getServerConfig() *tls.Config {
	capool := x509.NewCertPool()
	if ok := capool.AppendCertsFromPEM([]byte(ca_s)); !ok {
		panic("Cannot add cert")
	}

	cert, err := tls.X509KeyPair([]byte(cert1_s), []byte(priv1_s))
	if err != nil {
		panic(err)
	}

	config := tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    capool,
	}
	config.Rand = rand.Reader

	return &config
}

func getClientConfig() *tls.Config {
	capool := x509.NewCertPool()
	if ok := capool.AppendCertsFromPEM([]byte(ca_s)); !ok {
		panic("Cannot add cert")
	}

	cert, err := tls.X509KeyPair([]byte(cert1_s), []byte(priv1_s))
	if err != nil {
		panic(err)
	}

	config := tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: false,
		ServerName:         "dummycert1",
		RootCAs:            capool,
	}
	config.Rand = rand.Reader

	return &config
}

func (s *ServerSuite) TestTLS(c *C) {
	handler := new(HandlerMock)
	server := NewServer()
	server.SetFormat(RFC3164)
	server.SetHandler(handler)
	server.ListenTCPTLS("0.0.0.0:5143", getServerConfig())

	server.Boot()
	go func(server *Server) {
		time.Sleep(100 * time.Millisecond)
		conn, err := tls.Dial("tcp", "127.0.0.1:5143", getClientConfig())
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		if _, err := io.WriteString(conn, fmt.Sprintf("%s\n", exampleSyslog)); err != nil {
			panic(err)
		}
		time.Sleep(100 * time.Millisecond)
		server.Kill()
	}(server)
	server.Wait()

	c.Check(handler.LastLogParts["hostname"], Equals, "hostname")
	c.Check(handler.LastLogParts["tag"], Equals, "tag")
	c.Check(handler.LastLogParts["content"], Equals, "content")
	c.Check(handler.LastLogParts["tls_peer"], Equals, "dummycert1")
	c.Check(handler.LastMessageLength, Equals, int64(len(exampleSyslog)))
	c.Check(handler.LastError, IsNil)
}

const (
	priv1_s = `-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDpnXkcNrzbCNcI
SqxHAmCeXpk55/0uPMw3h98i9YYzX68FBFpREXO86ZOyLarqdxuqTt9gRMd8Byds
4JwsYiq2qKAWqzU9MfAqzcwiwAT/YFUB/JwZNzQkvfIlMKxjaMl4owVzjhBQQ3Tj
qtjPuIC+pXW5Kxt6K8PHOA49C+2B+X88uW9XYMOshY19XdAx2rNxgqu67p/rWbVW
eSvF4BNa1munScpaz0hxcarjxREb3K2+KbsnRRaJ7xlOsYD5d+sAI+e2cO6DulRj
Y3wMYQMneicfYBnzoS18ovqA1f70KJZ962VL4S40DELJa69i9mq2nEELpiFLBA+f
qV4qKjW9AgMBAAECggEADXiCGklhvHOXCqhbpMCTV652wWsKI1doIy+Xg0mLEn1K
90wX9SK/fL4vQQ/3EgwKMVjY8pEku5ciA9ozxy9l7SBuEsCOklfF1IIHal2OLDee
zz2EtsODIzc8tj5HQngxXd5wmwgvEqHBJLueQuQNsHCUCDhfHj1VzbACyixc5qij
Iuoipjy0VizAt+UAYeIJPJEkcpJ1FkFas6ns0kOXkLcyUq98qoCW3WdJFlF8Qa95
3xFL3HZWJWGIJv0zKzNjGbQJ5OKr0C+yonOtahyo3ueFhpx8Ti/WzurNEz6B3mMt
U6j6il1G5YzxahHa/B5DE0mtxF8OnGPn1fYv3vwhNQKBgQD55GIyviEs9En4cp7w
Q+pEJohE6WjweB6U9/Jk1ftHcWcokL8vTs4RWt08usIj6AziqiflbHaNGUGKTVfe
glnqtkAvI+0RNeJK3DuZ7FCHX/+tHmPkg3+6RlZ499bNhJn/BTbbuzm5C4bndiqi
fTF2UduXsv1V7M9lFSZcYeSXkwKBgQDvUz3c2lNDViKXo90AYtW8aTvFvtTmV1vZ
X6K41XIv8nXl8x/0Zn3noFvDnFaveiWV7lSwa3dyOTfrxxFGTtcfLFghYCTXfOP4
2mP67vIiy3LcOM3yMQ1mBM4qjOLvzNXxt0dj4HeuaaHyUrGinGMe926wY1/nhMi8
kdOQgTWvbwKBgQC6iBgk+HebLt7obebmQkvkgz7E8dY7ae6qFEsDqhbfxW7TgPi1
P4XivojWhDHWy6iSqaEOSGBWArxBmGo21eZ4pYJTreWQK0C30J1M0HFsG+SmPUEj
mmUFjuuNcLMOxiSNkD7a1m7ICiqxLCu3DuyU/ZWFLz6bnSFSuu7fltMjsQKBgH3D
SYPwOsbs0ZrMIkucpGKxDhb5FBnDGGIfTnxAthOaHvhqjYU6ArmgW/hsBGWME4o5
Rsm6f3dHuCovXtWKgqNAA0PuqQ2P9KCF6vonbJh6Pu6Y7yhxPHA64Dgd9vc6tcai
oGJMx7egjNixOeWQtsnEDqekYPZhobbuDrYmIBcDAoGAV19q5k0jDC/5lJ+jHOZe
vyGy/C2bBan5lFDTuDd0iZIdLGPvgAfxmrckyMjTNZRzW0HZcj/UfcOw9VP+Xo5k
pjjNaPFqGrUDDij6Ko9039UyY0xDEKJBXaGI0Vq3XdX1BDjF9zuv3V9PEXN3ZDrr
xfzlDcanaizNpgbSs7klC/Q=
-----END RSA PRIVATE KEY-----`

	cert1_s = `-----BEGIN CERTIFICATE-----
MIIDQDCCAiigAwIBAgIJAOxbRYdnH83LMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNV
BAYTAkNOMQswCQYDVQQIDAJHRDELMAkGA1UEBwwCU1oxEzARBgNVBAoMCkFjbWUs
IEluYy4xFTATBgNVBAMMDEFjbWUgUm9vdCBDQTAeFw0yMTEyMDMxMDI3MzhaFw0y
MjEyMDMxMDI3MzhaMFExCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJHRDELMAkGA1UE
BwwCU1oxEzARBgNVBAoMCkFjbWUsIEluYy4xEzARBgNVBAMMCmR1bW15Y2VydDEw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpnXkcNrzbCNcISqxHAmCe
Xpk55/0uPMw3h98i9YYzX68FBFpREXO86ZOyLarqdxuqTt9gRMd8Byds4JwsYiq2
qKAWqzU9MfAqzcwiwAT/YFUB/JwZNzQkvfIlMKxjaMl4owVzjhBQQ3TjqtjPuIC+
pXW5Kxt6K8PHOA49C+2B+X88uW9XYMOshY19XdAx2rNxgqu67p/rWbVWeSvF4BNa
1munScpaz0hxcarjxREb3K2+KbsnRRaJ7xlOsYD5d+sAI+e2cO6DulRjY3wMYQMn
eicfYBnzoS18ovqA1f70KJZ962VL4S40DELJa69i9mq2nEELpiFLBA+fqV4qKjW9
AgMBAAGjGTAXMBUGA1UdEQQOMAyCCmR1bW15Y2VydDEwDQYJKoZIhvcNAQEFBQAD
ggEBAFP/Xl8b1ZqW/E9q+RkQm0oNcU+rnWha+sOLQt3Jy1wKpzwNLsklkg70AyDs
1l2gSH3iPqJp6/0r8tIue962KjmKjHrcNPH0/Ubc31VmiPIQI9pcI6nJ58mqu4F7
jpN7nAH521aW327tVJgPkTpKeATP/fyQrgHK2IuYr3QqISujh2QFuGLw/wZVfjI2
T/zfPl+C13E5F2KqE5oBCPSIlIloN6NjHMDoiYRvHMcpCo+YSHDUaLHQ9ex8yve/
tjECgHDJsewgqsV9dlvg5+M7FHliSeQ+NHg+lqMojG7/NcqhF0f4aZ9ARKy0+CKr
NFolRbbBpUi5TaC+WGNIYXgi3MM=
-----END CERTIFICATE-----
`
	ca_s = `-----BEGIN CERTIFICATE-----
MIIDIjCCAgoCCQDATLUiZMmfWzANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJD
TjELMAkGA1UECAwCR0QxCzAJBgNVBAcMAlNaMRMwEQYDVQQKDApBY21lLCBJbmMu
MRUwEwYDVQQDDAxBY21lIFJvb3QgQ0EwHhcNMjExMjAzMTAyMDU1WhcNMjIxMjAz
MTAyMDU1WjBTMQswCQYDVQQGEwJDTjELMAkGA1UECAwCR0QxCzAJBgNVBAcMAlNa
MRMwEQYDVQQKDApBY21lLCBJbmMuMRUwEwYDVQQDDAxBY21lIFJvb3QgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDvwVG0Nd24SX2YqU5xUXjvOccp
HOr1wGjyyO9tdF3mTVEsDrqmg0+U1AJ+2oTQdKNohDCnBrOQ6FOBVjQ9eNN+Q5jo
breTiKNABXKK8/pl6DW8tZA19t9MLNtGWlmw7xDyrn2q5dwsqmnQ6qlsspliJhlK
unaAd7vHbyo1u6X+/zksHnneOwMz8HBmR4VoJQc+HMaiT29OXO/wTLULz92j9qq4
IUENm6VkITeQaBswIX2mCiFci2Hum+ioEzAnNbIl4L+LThQ8ojIo01K2m8R1GjMr
omdZgv2k15Awr8JKrHnf0aS5fQRJG7qNq5LtLppn4NIpubEH9mEy/JbY7UhjAgMB
AAEwDQYJKoZIhvcNAQELBQADggEBAA/PHq9cORyTZXxoaQiGEqLOXlTfGJ5fG9S3
M8kSUEj62CoTd+RVi4bMDNnTh1Vw2DQaEom6qXpgOdIt+ZdNHwm140sIbCcKuKpu
1BuJr742KwJXiJDLD80ugmBJgGRM6RD/5vPWspBrTo5yvIx+Re5DNESetVCDjyaK
Pb+DI/mAw5TIjYIod2C9EGcB4wFAqWItpAaqqBpodCt18pRobyyphnUscdAyf12F
i8WitSdT/FlNzqSS5BXkglxbyGiOfM8SuQxJFjcUYgPq8VDSVYL9F2mc6LC6PHAf
EdpKh8ORPXxctFlRu87SJK0jSU/VSeECZsuKG4gSIKIl+idiNsY=
-----END CERTIFICATE-----
`
)
