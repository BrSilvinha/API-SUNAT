package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"API-SUNAT2/model"
	"API-SUNAT2/util"

	"github.com/sirupsen/logrus"
)

type UBLConverterService struct {
	validator    *ValidationService
	converter    *UBLConverter
	signer       *DigitalSignatureService
	logService   *util.LogService
	xmlStorePath string
}

// GetValidator retorna el validador para uso externo
func (s *UBLConverterService) GetValidator() *ValidationService {
	return s.validator
}

// GetXMLStorePath retorna la ruta de almacenamiento XML
func (s *UBLConverterService) GetXMLStorePath() string {
	return s.xmlStorePath
}

func NewUBLConverterService(xmlStorePath string) *UBLConverterService {
	logService := util.NewLogService()
	return &UBLConverterService{
		validator:    NewValidationService(logService.GetLogger()),
		converter:    NewUBLConverter(logService.GetLogger()),
		signer:       NewDigitalSignatureService(logService.GetLogger()),
		logService:   logService,
		xmlStorePath: xmlStorePath,
	}
}

func (s *UBLConverterService) ProcessDocument(doc *model.BusinessDocument, certPEM, keyPEM []byte) (*model.APIResponse, error) {
	startTime := time.Now()
	correlationID := util.GenerateCorrelationID()

	// Log inicio del proceso
	s.logService.LogInfo(correlationID, "PROCESS_DOCUMENT", doc.Type, fmt.Sprintf("%s-%s", doc.Series, doc.Number), "Iniciando procesamiento de documento")

	// Validar documento
	validationErrors := s.validator.ValidateBusinessDocument(doc)
	if len(validationErrors) > 0 {
		s.logService.LogError(correlationID, "VALIDATION_ERROR", doc.Type, fmt.Sprintf("%s-%s", doc.Series, doc.Number), "VALIDATION_FAILED", "Documento no válido")
		return &model.APIResponse{
			Status:           "ERROR",
			CorrelationID:    correlationID,
			ProcessedAt:      time.Now(),
			ErrorCode:        "VALIDATION_FAILED",
			ErrorMessage:     "Documento no válido",
			ValidationErrors: validationErrors,
		}, nil
	}

	// Convertir a UBL
	xmlData, err := s.converter.ConvertToUBL(doc)
	if err != nil {
		s.logService.LogError(correlationID, "CONVERSION_ERROR", doc.Type, fmt.Sprintf("%s-%s", doc.Series, doc.Number), "CONVERSION_FAILED", err.Error())
		return &model.APIResponse{
			Status:        "ERROR",
			CorrelationID: correlationID,
			ProcessedAt:   time.Now(),
			ErrorCode:     "CONVERSION_FAILED",
			ErrorMessage:  fmt.Sprintf("Error en conversión UBL: %v", err),
		}, nil
	}

	// Firmar digitalmente
	signedXML, err := s.signer.SignXML(xmlData, certPEM, keyPEM)
	if err != nil {
		s.logService.LogError(correlationID, "DIGITAL_SIGNATURE_ERROR", doc.Type, fmt.Sprintf("%s-%s", doc.Series, doc.Number), "SIGNATURE_FAILED", err.Error())
		return &model.APIResponse{
			Status:        "ERROR",
			CorrelationID: correlationID,
			ProcessedAt:   time.Now(),
			ErrorCode:     "SIGNATURE_FAILED",
			ErrorMessage:  fmt.Sprintf("Error en firma digital: %v", err),
		}, nil
	}

	// Generar nombre de archivo
	fileName := fmt.Sprintf("%s-%s-%s-%s.xml", doc.Issuer.DocumentID, doc.Type, doc.Series, doc.Number)
	filePath := filepath.Join(s.xmlStorePath, fileName)

	// Crear directorio si no existe
	if err := os.MkdirAll(s.xmlStorePath, 0755); err != nil {
		s.logService.LogError(correlationID, "DIR_CREATE_ERROR", doc.Type, fmt.Sprintf("%s-%s", doc.Series, doc.Number), "DIR_CREATE_FAILED", err.Error())
		return &model.APIResponse{
			Status:        "ERROR",
			CorrelationID: correlationID,
			ProcessedAt:   time.Now(),
			ErrorCode:     "DIR_CREATE_FAILED",
			ErrorMessage:  fmt.Sprintf("Error al crear directorio: %v", err),
		}, nil
	}

	// Guardar XML firmado
	err = os.WriteFile(filePath, signedXML, 0644)
	if err != nil {
		s.logService.LogError(correlationID, "FILE_SAVE_ERROR", doc.Type, fmt.Sprintf("%s-%s", doc.Series, doc.Number), "SAVE_FAILED", err.Error())
		return &model.APIResponse{
			Status:        "ERROR",
			CorrelationID: correlationID,
			ProcessedAt:   time.Now(),
			ErrorCode:     "SAVE_FAILED",
			ErrorMessage:  fmt.Sprintf("Error al guardar archivo: %v", err),
		}, nil
	}

	// Crear archivo ZIP
	zipPath, err := util.ZipXMLFile(filePath)
	if err != nil {
		s.logService.LogError(correlationID, "ZIP_ERROR", doc.Type, fmt.Sprintf("%s-%s", doc.Series, doc.Number), "ZIP_FAILED", err.Error())
		return &model.APIResponse{
			Status:        "ERROR",
			CorrelationID: correlationID,
			ProcessedAt:   time.Now(),
			ErrorCode:     "ZIP_FAILED",
			ErrorMessage:  fmt.Sprintf("Error al crear ZIP: %v", err),
		}, nil
	}

	// Calcular hash del XML
	hash := sha256.Sum256(signedXML)
	xmlHash := hex.EncodeToString(hash[:])

	// Calcular duración
	duration := time.Since(startTime).Milliseconds()

	// Log éxito
	s.logService.LogInfo(correlationID, "PROCESS_SUCCESS", doc.Type, fmt.Sprintf("%s-%s", doc.Series, doc.Number), "Documento procesado exitosamente")

	// Retornar respuesta exitosa
	response := &model.APIResponse{
		Status:        "SUCCESS",
		CorrelationID: correlationID,
		DocumentID:    fmt.Sprintf("%s-%s-%s-%s", doc.Issuer.DocumentID, doc.Type, doc.Series, doc.Number),
		XMLPath:       zipPath,
		XMLHash:       xmlHash,
		ProcessedAt:   time.Now(),
		Duration:      duration,
		Data: map[string]interface{}{
			"fileName": fileName,
			"fileSize": len(signedXML),
			"zipSize":  getFileSize(zipPath),
		},
		Message: fmt.Sprintf("El archivo ZIP fue generado exitosamente en: %s", zipPath),
	}

	return response, nil
}

func getFileSize(filePath string) int64 {
	info, err := os.Stat(filePath)
	if err != nil {
		return 0
	}
	return info.Size()
}

type UBLConverter struct {
	logger *logrus.Logger
}

func NewUBLConverter(logger *logrus.Logger) *UBLConverter {
	return &UBLConverter{logger: logger}
}

func (c *UBLConverter) ConvertToUBL(doc *model.BusinessDocument) ([]byte, error) {
	switch doc.Type {
	case "01", "03": // Factura o Boleta
		return c.convertToInvoice(doc)
	case "07": // Nota de Crédito
		return c.convertToCreditNote(doc)
	case "08": // Nota de Débito
		return c.convertToDebitNote(doc)
	default:
		return nil, fmt.Errorf("unsupported document type: %s", doc.Type)
	}
}

func (c *UBLConverter) convertToInvoice(doc *model.BusinessDocument) ([]byte, error) {
	invoice := &model.UBLInvoice{
		XMLName: xml.Name{
			Space: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
			Local: "Invoice",
		},
		// Remover o corregir las URLs problemáticas
		UBLExtensions: &model.UBLExtensions{
			UBLExtension: model.UBLExtension{
				ExtensionContent: model.ExtensionContent{
					Signature: model.XMLSignature{}, // Se reemplazará por la firma real
				},
			},
		},
		UBLVersionID: "2.1",
		CustomizationID: model.UBLIDWithScheme{
			SchemeAgencyName: "PE:SUNAT",
			Value:            "2.0",
		},
		ProfileID: model.UBLIDWithScheme{
			SchemeAgencyName: "PE:SUNAT",
			SchemeName:       "Tipo de Operacion",
			// Remover SchemeURI problemática o usar una URL local
			Value: "0101",
		},
		ID:        fmt.Sprintf("%s-%s", doc.Series, doc.Number),
		IssueDate: doc.IssueDate,
		IssueTime: "10:30:00",
		DueDate:   doc.IssueDate,
		InvoiceTypeCode: model.UBLTypeCode{
			ListAgencyName: "PE:SUNAT",
			ListID:         "0101",
			ListName:       "Tipo de Documento",
			// Remover ListURI problemática
			Name:  "Tipo de Operacion",
			Value: doc.Type,
		},
		DocumentCurrencyCode: model.UBLIDWithScheme{
			SchemeAgencyName: "United Nations Economic Commission for Europe",
			SchemeID:         "ISO 4217 Alpha",
			SchemeName:       "Currency",
			Value:            doc.Currency,
		},
		LineCountNumeric:        len(doc.Items),
		Note:                    c.getDocumentNote(doc.Type),
		Signature:               c.createUBLSignature(doc),
		AccountingSupplierParty: c.convertParty(doc.Issuer),
		AccountingCustomerParty: c.convertParty(doc.Customer),
		PaymentTerms: []model.UBLPaymentTerms{
			{
				ID:             "FormaPago",
				PaymentMeansID: "Contado",
			},
		},
		TaxTotal:           c.convertTaxTotals(doc.Taxes, doc.Currency),
		LegalMonetaryTotal: c.convertLegalMonetaryTotal(doc.Totals, doc.Currency),
		InvoiceLines:       c.convertInvoiceLines(doc.Items, doc.Currency),
	}

	xmlData, err := xml.MarshalIndent(invoice, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error marshaling invoice XML: %v", err)
	}

	// Agregar declaración XML y namespaces
	xmlDeclaration := []byte(`<?xml version="1.0" encoding="UTF-8"?>`)
	xmlWithNamespaces := c.addNamespaces(xmlData, "Invoice")

	return append(xmlDeclaration, append([]byte("\n"), xmlWithNamespaces...)...), nil
}

func (c *UBLConverter) convertToCreditNote(doc *model.BusinessDocument) ([]byte, error) {
	creditNote := &model.UBLCreditNote{
		Xmlns:        "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2",
		XmlnsCac:     "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
		XmlnsCbc:     "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
		XmlnsDs:      "http://www.w3.org/2000/09/xmldsig#",
		XmlnsExt:     "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
		UBLVersionID: "2.1",
		CustomizationID: model.UBLIDWithScheme{
			SchemeAgencyName: "PE:SUNAT",
			Value:            "2.0",
		},
		ProfileID: model.UBLIDWithScheme{
			SchemeAgencyName: "PE:SUNAT",
			SchemeName:       "Tipo de Operacion",
			SchemeURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo51",
			Value:            "0101",
		},
		ID:        fmt.Sprintf("%s-%s", doc.Series, doc.Number),
		IssueDate: doc.IssueDate,
		IssueTime: "10:30:00",
		CreditNoteTypeCode: model.UBLTypeCode{
			ListAgencyName: "PE:SUNAT",
			ListID:         "0101",
			ListName:       "Tipo de Documento",
			ListURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo09",
			Name:           "Tipo de Operacion",
			Value:          doc.Type,
		},
		DocumentCurrencyCode: model.UBLIDWithScheme{
			SchemeAgencyName: "United Nations Economic Commission for Europe",
			SchemeID:         "ISO 4217 Alpha",
			SchemeName:       "Currency",
			Value:            doc.Currency,
		},
		LineCountNumeric:        len(doc.Items),
		DiscrepancyResponse:     c.createDiscrepancyResponse(doc.Reference),
		BillingReference:        c.createBillingReference(doc.Reference),
		AccountingSupplierParty: c.convertParty(doc.Issuer),
		AccountingCustomerParty: c.convertParty(doc.Customer),
		PaymentTerms: []model.UBLPaymentTerms{
			{
				ID:             "FormaPago",
				PaymentMeansID: "Contado",
			},
		},
		TaxTotal:           c.convertTaxTotals(doc.Taxes, doc.Currency),
		LegalMonetaryTotal: c.convertLegalMonetaryTotal(doc.Totals, doc.Currency),
		CreditNoteLines:    c.convertCreditNoteLines(doc.Items, doc.Currency),
	}

	xmlData, err := xml.MarshalIndent(creditNote, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error marshaling credit note XML: %v", err)
	}

	xmlDeclaration := []byte(`<?xml version="1.0" encoding="UTF-8"?>`)
	return append(xmlDeclaration, append([]byte("\n"), xmlData...)...), nil
}

func (c *UBLConverter) convertToDebitNote(doc *model.BusinessDocument) ([]byte, error) {
	debitNote := &model.UBLDebitNote{
		Xmlns:        "urn:oasis:names:specification:ubl:schema:xsd:DebitNote-2",
		XmlnsCac:     "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
		XmlnsCbc:     "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
		XmlnsDs:      "http://www.w3.org/2000/09/xmldsig#",
		XmlnsExt:     "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
		UBLVersionID: "2.1",
		CustomizationID: model.UBLIDWithScheme{
			SchemeAgencyName: "PE:SUNAT",
			Value:            "2.0",
		},
		ProfileID: model.UBLIDWithScheme{
			SchemeAgencyName: "PE:SUNAT",
			SchemeName:       "Tipo de Operacion",
			SchemeURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo51",
			Value:            "0101",
		},
		ID:        fmt.Sprintf("%s-%s", doc.Series, doc.Number),
		IssueDate: doc.IssueDate,
		IssueTime: "10:30:00",
		DebitNoteTypeCode: model.UBLTypeCode{
			ListAgencyName: "PE:SUNAT",
			ListID:         "0101",
			ListName:       "Tipo de Documento",
			ListURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo10",
			Name:           "Tipo de Operacion",
			Value:          doc.Type,
		},
		DocumentCurrencyCode: model.UBLIDWithScheme{
			SchemeAgencyName: "United Nations Economic Commission for Europe",
			SchemeID:         "ISO 4217 Alpha",
			SchemeName:       "Currency",
			Value:            doc.Currency,
		},
		LineCountNumeric:        len(doc.Items),
		DiscrepancyResponse:     c.createDiscrepancyResponse(doc.Reference),
		BillingReference:        c.createBillingReference(doc.Reference),
		AccountingSupplierParty: c.convertParty(doc.Issuer),
		AccountingCustomerParty: c.convertParty(doc.Customer),
		PaymentTerms: []model.UBLPaymentTerms{
			{
				ID:             "FormaPago",
				PaymentMeansID: "Contado",
			},
		},
		TaxTotal:           c.convertTaxTotals(doc.Taxes, doc.Currency),
		LegalMonetaryTotal: c.convertLegalMonetaryTotal(doc.Totals, doc.Currency),
		DebitNoteLines:     c.convertDebitNoteLines(doc.Items, doc.Currency),
	}

	xmlData, err := xml.MarshalIndent(debitNote, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error marshaling debit note XML: %v", err)
	}

	xmlDeclaration := []byte(`<?xml version="1.0" encoding="UTF-8"?>`)
	return append(xmlDeclaration, append([]byte("\n"), xmlData...)...), nil
}

// Funciones auxiliares optimizadas
func (c *UBLConverter) getDocumentNote(docType string) string {
	if docType == "03" {
		return "TRANSFERENCIA GRATUITA DE UN BIEN Y/O SERVICIO PRESTADO GRATUITAMENTE"
	}
	return ""
}

func (c *UBLConverter) addNamespaces(xmlData []byte, rootElement string) []byte {
	xmlStr := string(xmlData)

	// Usar URLs locales o URLs que funcionen correctamente
	namespaces := `xmlns="urn:oasis:names:specification:ubl:schema:xsd:` + rootElement + `-2" ` +
		`xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" ` +
		`xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" ` +
		`xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ` +
		`xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2" ` +
		`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`

	// Reemplazar el elemento raíz con namespaces
	oldRoot := fmt.Sprintf("<%s>", rootElement)
	newRoot := fmt.Sprintf("<%s %s>", rootElement, namespaces)
	xmlStr = strings.Replace(xmlStr, oldRoot, newRoot, 1)

	return []byte(xmlStr)
}

// Función auxiliar para crear declaración XML completa
func (c *UBLConverter) createXMLDeclaration(xmlData []byte, rootElement string) []byte {
	xmlDeclaration := `<?xml version="1.0" encoding="UTF-8"?>`
	xmlWithNamespaces := c.addNamespaces(xmlData, rootElement)

	return []byte(fmt.Sprintf("%s\n%s", xmlDeclaration, string(xmlWithNamespaces)))
}

func (c *UBLConverter) createDiscrepancyResponse(ref *model.DocumentReference) []model.UBLDiscrepancyResponse {
	if ref == nil {
		return []model.UBLDiscrepancyResponse{}
	}

	return []model.UBLDiscrepancyResponse{
		{
			ReferenceID:  ref.DocumentID,
			ResponseCode: "01",
			Description:  ref.Reason,
		},
	}
}

func (c *UBLConverter) createBillingReference(ref *model.DocumentReference) []model.UBLBillingReference {
	if ref == nil {
		return []model.UBLBillingReference{}
	}

	return []model.UBLBillingReference{
		{
			InvoiceDocumentReference: model.UBLDocumentReference{
				ID:               ref.DocumentID,
				IssueDate:        ref.IssueDate,
				DocumentTypeCode: ref.DocumentType,
			},
		},
	}
}

func (c *UBLConverter) createUBLSignature(doc *model.BusinessDocument) *model.UBLSignature {
	return &model.UBLSignature{
		ID: fmt.Sprintf("%s-%s", doc.Series, doc.Number),
		SignatoryParty: model.UBLSignatoryParty{
			PartyIdentification: model.UBLPartyIdentification{
				ID: model.UBLIDWithScheme{
					Value: doc.Issuer.DocumentID,
				},
			},
			PartyName: model.UBLPartyName{
				Name: doc.Issuer.Name,
			},
		},
		DigitalSignatureAttachment: model.UBLDigitalSignatureAttachment{
			ExternalReference: model.UBLExternalReference{
				URI: "#SignatureSP",
			},
		},
	}
}

func (c *UBLConverter) convertParty(party model.Party) model.UBLParty {
	schemeID := "6"
	if party.DocumentType == "1" {
		schemeID = "1"
	}

	return model.UBLParty{
		Party: model.UBLPartyDetail{
			PartyIdentification: []model.UBLPartyIdentification{
				{
					ID: model.UBLIDWithScheme{
						SchemeAgencyName: "PE:SUNAT",
						SchemeID:         schemeID,
						SchemeName:       "Documento de Identidad",
						SchemeURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo06",
						Value:            party.DocumentID,
					},
				},
			},
			PartyName: []model.UBLPartyName{
				{Name: party.Name},
			},
			RegistrationAddress: c.createRegistrationAddress(party.Address),
			PartyTaxScheme:      c.createPartyTaxScheme(party, schemeID),
			PartyLegalEntity:    c.createPartyLegalEntity(party),
			Contact: &model.UBLContact{
				Name: "",
			},
		},
	}
}

func (c *UBLConverter) createRegistrationAddress(address model.Address) model.UBLRegistrationAddress {
	return model.UBLRegistrationAddress{
		ID: model.UBLIDWithScheme{
			SchemeAgencyName: "PE:INEI",
			SchemeName:       "Ubigeos",
			Value:            "140101", // Lima por defecto
		},
		AddressTypeCode: model.UBLIDWithScheme{
			SchemeAgencyName: "PE:SUNAT",
			SchemeName:       "Establecimientos anexos",
			Value:            "0000",
		},
		CityName:         address.City,
		CountrySubentity: address.Province,
		District:         address.District,
		AddressLine: model.UBLAddressLine{
			Line: fmt.Sprintf("%s - %s - %s - %s", address.Street, address.District, address.Province, address.Department),
		},
		Country: model.UBLCountry{
			IdentificationCode: model.UBLIDWithScheme{
				SchemeAgencyName: "United Nations Economic Commission for Europe",
				SchemeID:         "ISO 3166-1",
				SchemeName:       "Country",
				Value:            address.Country,
			},
		},
	}
}

func (c *UBLConverter) createPartyTaxScheme(party model.Party, schemeID string) []model.UBLPartyTaxScheme {
	return []model.UBLPartyTaxScheme{
		{
			RegistrationName: party.Name,
			CompanyID: model.UBLIDWithScheme{
				SchemeAgencyName: "PE:SUNAT",
				SchemeID:         schemeID,
				SchemeName:       "SUNAT:Identificador de Documento de Identidad",
				SchemeURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo06",
				Value:            party.DocumentID,
			},
			TaxScheme: model.UBLTaxScheme{
				ID: model.UBLIDWithScheme{
					SchemeAgencyName: "PE:SUNAT",
					SchemeID:         schemeID,
					SchemeName:       "SUNAT:Identificador de Documento de Identidad",
					SchemeURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo06",
					Value:            party.DocumentID,
				},
			},
		},
	}
}

func (c *UBLConverter) createPartyLegalEntity(party model.Party) []model.UBLPartyLegalEntity {
	return []model.UBLPartyLegalEntity{
		{
			RegistrationName:    party.Name,
			RegistrationAddress: c.createRegistrationAddress(party.Address),
		},
	}
}

func (c *UBLConverter) convertTaxTotals(taxes []model.TaxTotal, currency string) []model.UBLTaxTotal {
	var taxTotals []model.UBLTaxTotal
	for _, tax := range taxes {
		taxTotal := model.UBLTaxTotal{
			TaxAmount: model.UBLAmountWithCurrency{
				CurrencyID: currency,
				Value:      tax.TaxAmount,
			},
			TaxSubtotals: []model.UBLTaxSubtotal{
				{
					TaxableAmount: model.UBLAmountWithCurrency{
						CurrencyID: currency,
						Value:      tax.TaxBase,
					},
					TaxAmount: model.UBLAmountWithCurrency{
						CurrencyID: currency,
						Value:      tax.TaxAmount,
					},
					TaxCategory: model.UBLTaxCategory{
						ID: model.UBLIDWithScheme{
							SchemeAgencyName: "United Nations Economic Commission for Europe",
							SchemeID:         "UN/ECE 5305",
							SchemeName:       "Tax Category Identifier",
							Value:            "S",
						},
						Percent: tax.TaxRate,
						TaxExemptionReasonCode: model.UBLIDWithScheme{
							SchemeAgencyName: "PE:SUNAT",
							SchemeName:       "Afectacion del IGV",
							SchemeURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo07",
							Value:            "10",
						},
						TaxScheme: model.UBLTaxScheme{
							ID: model.UBLIDWithScheme{
								SchemeAgencyName: "PE:SUNAT",
								SchemeID:         "UN/ECE 5153",
								Value:            tax.TaxType,
							},
							Name:        c.getTaxName(tax.TaxType),
							TaxTypeCode: "VAT",
						},
					},
				},
			},
		}
		taxTotals = append(taxTotals, taxTotal)
	}
	return taxTotals
}

func (c *UBLConverter) getTaxName(taxType string) string {
	switch taxType {
	case "1000":
		return "IGV"
	case "2000":
		return "ISC"
	case "7152":
		return "ICBPER"
	default:
		return "TAX"
	}
}

func (c *UBLConverter) convertLegalMonetaryTotal(totals model.DocumentTotals, currency string) model.UBLLegalMonetaryTotal {
	return model.UBLLegalMonetaryTotal{
		LineExtensionAmount: model.UBLAmountWithCurrency{
			CurrencyID: currency,
			Value:      totals.SubTotal,
		},
		TaxInclusiveAmount: model.UBLAmountWithCurrency{
			CurrencyID: currency,
			Value:      totals.TotalAmount,
		},
		PayableAmount: model.UBLAmountWithCurrency{
			CurrencyID: currency,
			Value:      totals.PayableAmount,
		},
	}
}

func (c *UBLConverter) convertInvoiceLines(items []model.DocumentItem, currency string) []model.UBLInvoiceLine {
	var lines []model.UBLInvoiceLine
	for i, item := range items {
		line := model.UBLInvoiceLine{
			ID: fmt.Sprintf("%d", i+1),
			InvoicedQuantity: model.UBLQuantityWithUnit{
				UnitCode:               item.UnitCode,
				UnitCodeListAgencyName: "United Nations Economic Commission for Europe",
				UnitCodeListID:         "UN/ECE rec 20",
				Value:                  item.Quantity,
			},
			LineExtensionAmount: model.UBLAmountWithCurrency{
				CurrencyID: currency,
				Value:      item.LineTotal,
			},
			PricingReference: &model.UBLPricingReference{
				AlternativeConditionPrice: model.UBLAlternativeConditionPrice{
					PriceAmount: model.UBLAmountWithCurrency{
						CurrencyID: currency,
						Value:      item.UnitPrice * item.Quantity,
					},
					PriceTypeCode: model.UBLIDWithScheme{
						SchemeAgencyName: "PE:SUNAT",
						SchemeName:       "Tipo de Precio",
						SchemeURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo16",
						Value:            "01",
					},
				},
			},
			TaxTotal: c.convertItemTaxes(item.Taxes, currency),
			Item: model.UBLItem{
				Description: item.Description,
				SellersItemIdentification: &model.UBLSellersItemIdentification{
					ID: item.ID,
				},
				CommodityClassification: &model.UBLCommodityClassification{
					ItemClassificationCode: model.UBLIDWithScheme{
						SchemeAgencyName: "GS1 US",
						SchemeID:         "UNSPSC",
						SchemeName:       "Item Classification",
						Value:            "10191509",
					},
				},
			},
			Price: model.UBLPrice{
				PriceAmount: model.UBLAmountWithCurrency{
					CurrencyID: currency,
					Value:      item.UnitPrice,
				},
			},
		}
		lines = append(lines, line)
	}
	return lines
}

func (c *UBLConverter) convertCreditNoteLines(items []model.DocumentItem, currency string) []model.UBLCreditNoteLine {
	var lines []model.UBLCreditNoteLine
	for i, item := range items {
		line := model.UBLCreditNoteLine{
			ID: fmt.Sprintf("%d", i+1),
			CreditedQuantity: model.UBLQuantityWithUnit{
				UnitCode:               item.UnitCode,
				UnitCodeListAgencyName: "United Nations Economic Commission for Europe",
				UnitCodeListID:         "UN/ECE rec 20",
				Value:                  item.Quantity,
			},
			LineExtensionAmount: model.UBLAmountWithCurrency{
				CurrencyID: currency,
				Value:      item.LineTotal,
			},
			PricingReference: &model.UBLPricingReference{
				AlternativeConditionPrice: model.UBLAlternativeConditionPrice{
					PriceAmount: model.UBLAmountWithCurrency{
						CurrencyID: currency,
						Value:      item.UnitPrice * item.Quantity,
					},
					PriceTypeCode: model.UBLIDWithScheme{
						SchemeAgencyName: "PE:SUNAT",
						SchemeName:       "Tipo de Precio",
						SchemeURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo16",
						Value:            "01",
					},
				},
			},
			TaxTotal: c.convertItemTaxes(item.Taxes, currency),
			Item: model.UBLItem{
				Description: item.Description,
				SellersItemIdentification: &model.UBLSellersItemIdentification{
					ID: item.ID,
				},
				CommodityClassification: &model.UBLCommodityClassification{
					ItemClassificationCode: model.UBLIDWithScheme{
						SchemeAgencyName: "GS1 US",
						SchemeID:         "UNSPSC",
						SchemeName:       "Item Classification",
						Value:            "10191509",
					},
				},
			},
			Price: model.UBLPrice{
				PriceAmount: model.UBLAmountWithCurrency{
					CurrencyID: currency,
					Value:      item.UnitPrice,
				},
			},
		}
		lines = append(lines, line)
	}
	return lines
}

func (c *UBLConverter) convertDebitNoteLines(items []model.DocumentItem, currency string) []model.UBLDebitNoteLine {
	var lines []model.UBLDebitNoteLine
	for i, item := range items {
		line := model.UBLDebitNoteLine{
			ID: fmt.Sprintf("%d", i+1),
			DebitedQuantity: model.UBLQuantityWithUnit{
				UnitCode:               item.UnitCode,
				UnitCodeListAgencyName: "United Nations Economic Commission for Europe",
				UnitCodeListID:         "UN/ECE rec 20",
				Value:                  item.Quantity,
			},
			LineExtensionAmount: model.UBLAmountWithCurrency{
				CurrencyID: currency,
				Value:      item.LineTotal,
			},
			PricingReference: &model.UBLPricingReference{
				AlternativeConditionPrice: model.UBLAlternativeConditionPrice{
					PriceAmount: model.UBLAmountWithCurrency{
						CurrencyID: currency,
						Value:      item.UnitPrice * item.Quantity,
					},
					PriceTypeCode: model.UBLIDWithScheme{
						SchemeAgencyName: "PE:SUNAT",
						SchemeName:       "Tipo de Precio",
						SchemeURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo16",
						Value:            "01",
					},
				},
			},
			TaxTotal: c.convertItemTaxes(item.Taxes, currency),
			Item: model.UBLItem{
				Description: item.Description,
				SellersItemIdentification: &model.UBLSellersItemIdentification{
					ID: item.ID,
				},
				CommodityClassification: &model.UBLCommodityClassification{
					ItemClassificationCode: model.UBLIDWithScheme{
						SchemeAgencyName: "GS1 US",
						SchemeID:         "UNSPSC",
						SchemeName:       "Item Classification",
						Value:            "10191509",
					},
				},
			},
			Price: model.UBLPrice{
				PriceAmount: model.UBLAmountWithCurrency{
					CurrencyID: currency,
					Value:      item.UnitPrice,
				},
			},
		}
		lines = append(lines, line)
	}
	return lines
}

func (c *UBLConverter) convertItemTaxes(taxes []model.Tax, currency string) []model.UBLTaxTotal {
	var taxTotals []model.UBLTaxTotal
	for _, tax := range taxes {
		taxTotal := model.UBLTaxTotal{
			TaxAmount: model.UBLAmountWithCurrency{
				CurrencyID: currency,
				Value:      tax.TaxAmount,
			},
			TaxSubtotals: []model.UBLTaxSubtotal{
				{
					TaxableAmount: model.UBLAmountWithCurrency{
						CurrencyID: currency,
						Value:      tax.TaxBase,
					},
					TaxAmount: model.UBLAmountWithCurrency{
						CurrencyID: currency,
						Value:      tax.TaxAmount,
					},
					TaxCategory: model.UBLTaxCategory{
						ID: model.UBLIDWithScheme{
							SchemeAgencyName: "United Nations Economic Commission for Europe",
							SchemeID:         "UN/ECE 5305",
							SchemeName:       "Tax Category Identifier",
							Value:            "S",
						},
						Percent: tax.TaxRate,
						TaxExemptionReasonCode: model.UBLIDWithScheme{
							SchemeAgencyName: "PE:SUNAT",
							SchemeName:       "Afectacion del IGV",
							SchemeURI:        "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo07",
							Value:            "10",
						},
						TaxScheme: model.UBLTaxScheme{
							ID: model.UBLIDWithScheme{
								SchemeAgencyName: "PE:SUNAT",
								SchemeID:         "UN/ECE 5153",
								SchemeName:       "Codigo de tributos",
								Value:            tax.TaxType,
							},
							Name:        c.getTaxName(tax.TaxType),
							TaxTypeCode: "VAT",
						},
					},
				},
			},
		}
		taxTotals = append(taxTotals, taxTotal)
	}
	return taxTotals
}
