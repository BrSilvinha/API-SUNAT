package service

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"strings"

	"API-SUNAT2/model"

	"github.com/sirupsen/logrus"
)

type DigitalSignatureService struct {
	logger *logrus.Logger
}

func NewDigitalSignatureService(logger *logrus.Logger) *DigitalSignatureService {
	return &DigitalSignatureService{logger: logger}
}

func (s *DigitalSignatureService) SignXML(xmlContent []byte, certPEM []byte, keyPEM []byte) ([]byte, error) {
	// Decodificar certificado y clave privada
	cert, err := s.parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	privateKey, err := s.parsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Canonicalizar el XML (simplificado)
	canonicalXML := s.canonicalizeXML(xmlContent)

	// Generar hash SHA-256 del contenido XML canonicalizado
	hash := sha256.Sum256(canonicalXML)

	// Firmar el hash
	signature, err := rsa.SignPKCS1v15(cryptorand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash: %v", err)
	}

	// Codificar firma en base64
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Codificar certificado en base64
	certBase64 := base64.StdEncoding.EncodeToString(cert.Raw)

	// Crear estructura XMLDSig
	xmlSignature := &model.XMLSignature{
		SignedInfo: model.SignedInfo{
			CanonicalizationMethod: model.CanonicalizationMethod{
				Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
			},
			SignatureMethod: model.SignatureMethod{
				Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			},
			Reference: model.Reference{
				URI: "",
				Transforms: model.Transforms{
					Transform: []model.Transform{
						{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
						{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
					},
				},
				DigestMethod: model.DigestMethod{
					Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
				},
				DigestValue: base64.StdEncoding.EncodeToString(hash[:]),
			},
		},
		SignatureValue: model.SignatureValue{
			Value: signatureBase64,
		},
		KeyInfo: model.KeyInfo{
			X509Data: model.X509Data{
				X509Certificate: certBase64,
			},
		},
	}

	// Insertar la firma en el XML
	signedXML, err := s.insertSignatureInXML(xmlContent, xmlSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to insert signature: %v", err)
	}

	return signedXML, nil
}

func (s *DigitalSignatureService) parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func (s *DigitalSignatureService) parsePrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	// Intentar parsear como PKCS1 primero
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Si falla, intentar como PKCS8
		key, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key (PKCS1: %v, PKCS8: %v)", err, err2)
		}

		// Convertir a *rsa.PrivateKey
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		privateKey = rsaKey
	}

	return privateKey, nil
}

func (s *DigitalSignatureService) canonicalizeXML(xmlContent []byte) []byte {
	// Canonicalización simplificada para UBL
	xmlStr := string(xmlContent)

	// Normalizar espacios en blanco
	xmlStr = strings.ReplaceAll(xmlStr, "\r\n", "\n")
	xmlStr = strings.ReplaceAll(xmlStr, "\r", "\n")

	// Remover espacios innecesarios entre elementos
	lines := strings.Split(xmlStr, "\n")
	var cleanLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			cleanLines = append(cleanLines, trimmed)
		}
	}

	return []byte(strings.Join(cleanLines, "\n"))
}

func (s *DigitalSignatureService) insertSignatureInXML(xmlContent []byte, xmlSignature *model.XMLSignature) ([]byte, error) {
	xmlStr := string(xmlContent)

	// Crear UBLExtensions con la firma XMLDSig
	ublExtensions := &model.UBLExtensions{
		UBLExtension: model.UBLExtension{
			ExtensionContent: model.ExtensionContent{
				Signature: *xmlSignature,
			},
		},
	}

	// Marshal UBLExtensions
	extensionsXML, err := xml.MarshalIndent(ublExtensions, "  ", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UBL extensions: %v", err)
	}

	// Buscar dónde insertar la firma
	// Buscar el cierre de la declaración XML
	xmlDeclEnd := strings.Index(xmlStr, "?>")
	if xmlDeclEnd == -1 {
		return nil, fmt.Errorf("XML declaration not found")
	}

	// Buscar el inicio del elemento raíz
	rootStart := strings.Index(xmlStr[xmlDeclEnd:], "<")
	if rootStart == -1 {
		return nil, fmt.Errorf("root element not found")
	}
	rootStart += xmlDeclEnd

	// Buscar el final del tag de apertura del elemento raíz
	rootTagEnd := strings.Index(xmlStr[rootStart:], ">")
	if rootTagEnd == -1 {
		return nil, fmt.Errorf("root element opening tag not closed")
	}
	rootTagEnd += rootStart + 1

	// Insertar UBLExtensions inmediatamente después del tag de apertura del elemento raíz
	result := xmlStr[:rootTagEnd] + "\n" + string(extensionsXML) + xmlStr[rootTagEnd:]

	return []byte(result), nil
}
