package service

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"API-SUNAT2/model"

	"github.com/sirupsen/logrus"
)

type ValidationService struct {
	logger *logrus.Logger
}

func NewValidationService(logger *logrus.Logger) *ValidationService {
	return &ValidationService{logger: logger}
}

func (v *ValidationService) ValidateBusinessDocument(doc *model.BusinessDocument) []model.ValidationError {
	var errors []model.ValidationError

	// Validaciones básicas
	errors = append(errors, v.validateBasicFields(doc)...)
	errors = append(errors, v.validateIssuer(doc.Issuer)...)
	errors = append(errors, v.validateCustomer(doc.Customer)...)
	errors = append(errors, v.validateItems(doc.Items)...)
	errors = append(errors, v.validateTotals(doc)...)
	errors = append(errors, v.validateTaxes(doc.Taxes)...)

	// Validaciones específicas por tipo de documento
	errors = append(errors, v.validateByDocumentType(doc)...)

	return errors
}

func (v *ValidationService) validateBasicFields(doc *model.BusinessDocument) []model.ValidationError {
	var errors []model.ValidationError

	// Validar tipo de documento
	if !v.isValidDocumentType(doc.Type) {
		errors = append(errors, model.ValidationError{
			Field:    "type",
			Expected: "Valid document type (01, 03, 07, 08)",
			Received: doc.Type,
			Rule:     "document_type_validation",
			Message:  "Document type is not valid",
		})
	}

	// Validar serie
	if err := v.validateSeries(doc.Series, doc.Type); err != nil {
		errors = append(errors, *err)
	}

	// Validar número
	if doc.Number == "" {
		errors = append(errors, model.ValidationError{
			Field:    "number",
			Expected: "Non-empty string",
			Received: doc.Number,
			Rule:     "required_field",
			Message:  "Document number is required",
		})
	}

	// Validar fecha
	if !v.isValidDate(doc.IssueDate) {
		errors = append(errors, model.ValidationError{
			Field:    "issueDate",
			Expected: "Valid date format YYYY-MM-DD",
			Received: doc.IssueDate,
			Rule:     "date_validation",
			Message:  "Issue date format is invalid",
		})
	}

	// Validar moneda
	if !v.isValidCurrency(doc.Currency) {
		errors = append(errors, model.ValidationError{
			Field:    "currency",
			Expected: "Valid currency code (PEN, USD, EUR)",
			Received: doc.Currency,
			Rule:     "currency_validation",
			Message:  "Currency code is not valid",
		})
	}

	return errors
}

func (v *ValidationService) validateIssuer(issuer model.Party) []model.ValidationError {
	var errors []model.ValidationError

	// Validar RUC del emisor
	if !v.isValidRUC(issuer.DocumentID) {
		errors = append(errors, model.ValidationError{
			Field:    "issuer.documentId",
			Expected: "Valid RUC format (11 digits)",
			Received: issuer.DocumentID,
			Rule:     "ruc_validation",
			Message:  "Issuer RUC format is invalid",
		})
	}

	// Validar tipo de documento del emisor (debe ser RUC)
	if issuer.DocumentType != "6" {
		errors = append(errors, model.ValidationError{
			Field:    "issuer.documentType",
			Expected: "6 (RUC)",
			Received: issuer.DocumentType,
			Rule:     "issuer_document_type",
			Message:  "Issuer must have RUC (document type 6)",
		})
	}

	// Validar nombre del emisor
	if strings.TrimSpace(issuer.Name) == "" {
		errors = append(errors, model.ValidationError{
			Field:    "issuer.name",
			Expected: "Non-empty string",
			Received: issuer.Name,
			Rule:     "required_field",
			Message:  "Issuer name is required",
		})
	}

	// Validar dirección del emisor
	errors = append(errors, v.validateAddress(issuer.Address, "issuer.address")...)

	return errors
}

func (v *ValidationService) validateCustomer(customer model.Party) []model.ValidationError {
	var errors []model.ValidationError

	// Validar documento del cliente
	if err := v.validateCustomerDocument(customer.DocumentType, customer.DocumentID); err != nil {
		errors = append(errors, *err)
	}

	// Validar nombre del cliente
	if strings.TrimSpace(customer.Name) == "" {
		errors = append(errors, model.ValidationError{
			Field:    "customer.name",
			Expected: "Non-empty string",
			Received: customer.Name,
			Rule:     "required_field",
			Message:  "Customer name is required",
		})
	}

	// Validar dirección del cliente
	errors = append(errors, v.validateAddress(customer.Address, "customer.address")...)

	return errors
}

func (v *ValidationService) validateItems(items []model.DocumentItem) []model.ValidationError {
	var errors []model.ValidationError

	if len(items) == 0 {
		errors = append(errors, model.ValidationError{
			Field:    "items",
			Expected: "At least one item",
			Received: "empty array",
			Rule:     "required_items",
			Message:  "Document must have at least one item",
		})
		return errors
	}

	for i, item := range items {
		prefix := fmt.Sprintf("items[%d]", i)

		// Validar descripción
		if strings.TrimSpace(item.Description) == "" {
			errors = append(errors, model.ValidationError{
				Field:    prefix + ".description",
				Expected: "Non-empty string",
				Received: item.Description,
				Rule:     "required_field",
				Message:  "Item description is required",
			})
		}

		// Validar cantidad
		if item.Quantity <= 0 {
			errors = append(errors, model.ValidationError{
				Field:    prefix + ".quantity",
				Expected: "Greater than 0",
				Received: fmt.Sprintf("%.2f", item.Quantity),
				Rule:     "quantity_validation",
				Message:  "Quantity must be greater than 0",
			})
		}

		// Validar precio unitario
		if item.UnitPrice <= 0 {
			errors = append(errors, model.ValidationError{
				Field:    prefix + ".unitPrice",
				Expected: "Greater than 0",
				Received: fmt.Sprintf("%.2f", item.UnitPrice),
				Rule:     "price_validation",
				Message:  "Unit price must be greater than 0",
			})
		}

		// Validar código de unidad
		if !v.isValidUnitCode(item.UnitCode) {
			errors = append(errors, model.ValidationError{
				Field:    prefix + ".unitCode",
				Expected: "Valid unit code (NIU, ZZ, etc.)",
				Received: item.UnitCode,
				Rule:     "unit_code_validation",
				Message:  "Invalid unit code",
			})
		}

		// Validar total de línea
		expectedLineTotal := item.Quantity * item.UnitPrice
		if fmt.Sprintf("%.2f", item.LineTotal) != fmt.Sprintf("%.2f", expectedLineTotal) {
			errors = append(errors, model.ValidationError{
				Field:    prefix + ".lineTotal",
				Expected: fmt.Sprintf("%.2f", expectedLineTotal),
				Received: fmt.Sprintf("%.2f", item.LineTotal),
				Rule:     "line_total_calculation",
				Message:  "Line total calculation mismatch",
			})
		}

		// Validar impuestos del item
		errors = append(errors, v.validateItemTaxes(item.Taxes, prefix+".taxes")...)
	}

	return errors
}

func (v *ValidationService) validateTotals(doc *model.BusinessDocument) []model.ValidationError {
	var errors []model.ValidationError

	// Calcular totales esperados
	expectedSubTotal := v.calculateSubTotal(doc.Items)
	expectedTotalTaxes := v.calculateTotalTaxes(doc.Taxes)
	expectedTotalAmount := expectedSubTotal + expectedTotalTaxes

	// Validar subtotal
	if fmt.Sprintf("%.2f", doc.Totals.SubTotal) != fmt.Sprintf("%.2f", expectedSubTotal) {
		errors = append(errors, model.ValidationError{
			Field:    "totals.subTotal",
			Expected: fmt.Sprintf("%.2f", expectedSubTotal),
			Received: fmt.Sprintf("%.2f", doc.Totals.SubTotal),
			Rule:     "subtotal_calculation",
			Message:  "Subtotal calculation mismatch",
		})
	}

	// Validar total de impuestos
	if fmt.Sprintf("%.2f", doc.Totals.TotalTaxes) != fmt.Sprintf("%.2f", expectedTotalTaxes) {
		errors = append(errors, model.ValidationError{
			Field:    "totals.totalTaxes",
			Expected: fmt.Sprintf("%.2f", expectedTotalTaxes),
			Received: fmt.Sprintf("%.2f", doc.Totals.TotalTaxes),
			Rule:     "total_taxes_calculation",
			Message:  "Total taxes calculation mismatch",
		})
	}

	// Validar total general
	if fmt.Sprintf("%.2f", doc.Totals.TotalAmount) != fmt.Sprintf("%.2f", expectedTotalAmount) {
		errors = append(errors, model.ValidationError{
			Field:    "totals.totalAmount",
			Expected: fmt.Sprintf("%.2f", expectedTotalAmount),
			Received: fmt.Sprintf("%.2f", doc.Totals.TotalAmount),
			Rule:     "total_amount_calculation",
			Message:  "Total amount calculation mismatch",
		})
	}

	// Validar monto a pagar
	if fmt.Sprintf("%.2f", doc.Totals.PayableAmount) != fmt.Sprintf("%.2f", expectedTotalAmount) {
		errors = append(errors, model.ValidationError{
			Field:    "totals.payableAmount",
			Expected: fmt.Sprintf("%.2f", expectedTotalAmount),
			Received: fmt.Sprintf("%.2f", doc.Totals.PayableAmount),
			Rule:     "payable_amount_validation",
			Message:  "Payable amount should equal total amount",
		})
	}

	return errors
}

func (v *ValidationService) validateTaxes(taxes []model.TaxTotal) []model.ValidationError {
	var errors []model.ValidationError

	for i, tax := range taxes {
		prefix := fmt.Sprintf("taxes[%d]", i)

		// Validar tipo de impuesto
		if !v.isValidTaxType(tax.TaxType) {
			errors = append(errors, model.ValidationError{
				Field:    prefix + ".taxType",
				Expected: "Valid tax type (1000=IGV, 2000=ISC, 7152=ICBPER)",
				Received: tax.TaxType,
				Rule:     "tax_type_validation",
				Message:  "Invalid tax type",
			})
		}

		// Validar cálculo de impuesto
		if tax.TaxRate > 0 && tax.TaxBase > 0 {
			expectedTaxAmount := tax.TaxBase * (tax.TaxRate / 100)
			if fmt.Sprintf("%.2f", tax.TaxAmount) != fmt.Sprintf("%.2f", expectedTaxAmount) {
				errors = append(errors, model.ValidationError{
					Field:    prefix + ".taxAmount",
					Expected: fmt.Sprintf("%.2f", expectedTaxAmount),
					Received: fmt.Sprintf("%.2f", tax.TaxAmount),
					Rule:     "tax_calculation",
					Message:  "Tax amount calculation mismatch",
				})
			}
		}
	}

	return errors
}

func (v *ValidationService) validateByDocumentType(doc *model.BusinessDocument) []model.ValidationError {
	var errors []model.ValidationError

	switch doc.Type {
	case "07", "08": // Notas de crédito y débito
		if doc.Reference == nil {
			errors = append(errors, model.ValidationError{
				Field:    "reference",
				Expected: "Reference document information",
				Received: "null",
				Rule:     "reference_required",
				Message:  "Credit/Debit notes must reference another document",
			})
		} else {
			// Validar documento de referencia
			errors = append(errors, v.validateDocumentReference(doc.Reference)...)
		}
	}

	return errors
}

// Funciones auxiliares de validación
func (v *ValidationService) validateSeries(series, docType string) *model.ValidationError {
	if series == "" {
		return &model.ValidationError{
			Field:    "series",
			Expected: "Non-empty series",
			Received: series,
			Rule:     "required_field",
			Message:  "Document series is required",
		}
	}

	// Validar formato de serie según tipo de documento (más flexible)
	var pattern string
	switch docType {
	case "01":
		pattern = "^F[0-9A-Z]{3}$" // Facturas: F001, F002, etc.
	case "03":
		pattern = "^B[0-9A-Z]{3}$" // Boletas: B001, B002, etc.
	case "07":
		pattern = "^(FC|BC|NC)[0-9A-Z]{2,3}$" // Notas de crédito
	case "08":
		pattern = "^(FD|BD|ND)[0-9A-Z]{2,3}$" // Notas de débito
	default:
		// Para otros tipos, aceptar cualquier serie válida
		pattern = "^[A-Z0-9]{3,4}$"
	}

	matched, _ := regexp.MatchString(pattern, series)
	if !matched {
		return &model.ValidationError{
			Field:    "series",
			Expected: fmt.Sprintf("Series matching pattern %s", pattern),
			Received: series,
			Rule:     "series_format",
			Message:  "Invalid series format for document type",
		}
	}

	return nil
}

func (v *ValidationService) validateCustomerDocument(docType, docID string) *model.ValidationError {
	switch docType {
	case "1": // DNI
		if !v.isValidDNI(docID) {
			return &model.ValidationError{
				Field:    "customer.documentId",
				Expected: "Valid DNI (8 digits)",
				Received: docID,
				Rule:     "dni_validation",
				Message:  "Invalid DNI format",
			}
		}
	case "6": // RUC
		if !v.isValidRUC(docID) {
			return &model.ValidationError{
				Field:    "customer.documentId",
				Expected: "Valid RUC (11 digits)",
				Received: docID,
				Rule:     "ruc_validation",
				Message:  "Invalid RUC format",
			}
		}
	case "4": // Carnet de extranjería
		if len(docID) < 8 || len(docID) > 12 {
			return &model.ValidationError{
				Field:    "customer.documentId",
				Expected: "Valid foreign ID (8-12 characters)",
				Received: docID,
				Rule:     "foreign_id_validation",
				Message:  "Invalid foreign ID format",
			}
		}
	case "7": // Pasaporte
		if len(docID) < 8 || len(docID) > 12 {
			return &model.ValidationError{
				Field:    "customer.documentId",
				Expected: "Valid passport (8-12 characters)",
				Received: docID,
				Rule:     "passport_validation",
				Message:  "Invalid passport format",
			}
		}
	default:
		return &model.ValidationError{
			Field:    "customer.documentType",
			Expected: "Valid document type (1=DNI, 4=CE, 6=RUC, 7=Passport)",
			Received: docType,
			Rule:     "document_type_validation",
			Message:  "Invalid customer document type",
		}
	}
	return nil
}

func (v *ValidationService) validateAddress(address model.Address, fieldPrefix string) []model.ValidationError {
	var errors []model.ValidationError

	if strings.TrimSpace(address.Street) == "" {
		errors = append(errors, model.ValidationError{
			Field:    fieldPrefix + ".street",
			Expected: "Non-empty string",
			Received: address.Street,
			Rule:     "required_field",
			Message:  "Street address is required",
		})
	}

	if strings.TrimSpace(address.City) == "" {
		errors = append(errors, model.ValidationError{
			Field:    fieldPrefix + ".city",
			Expected: "Non-empty string",
			Received: address.City,
			Rule:     "required_field",
			Message:  "City is required",
		})
	}

	if strings.TrimSpace(address.District) == "" {
		errors = append(errors, model.ValidationError{
			Field:    fieldPrefix + ".district",
			Expected: "Non-empty string",
			Received: address.District,
			Rule:     "required_field",
			Message:  "District is required",
		})
	}

	if strings.TrimSpace(address.Country) == "" {
		errors = append(errors, model.ValidationError{
			Field:    fieldPrefix + ".country",
			Expected: "Non-empty string",
			Received: address.Country,
			Rule:     "required_field",
			Message:  "Country is required",
		})
	}

	return errors
}

func (v *ValidationService) validateItemTaxes(taxes []model.Tax, fieldPrefix string) []model.ValidationError {
	var errors []model.ValidationError

	for i, tax := range taxes {
		prefix := fmt.Sprintf("%s[%d]", fieldPrefix, i)

		if !v.isValidTaxType(tax.TaxType) {
			errors = append(errors, model.ValidationError{
				Field:    prefix + ".taxType",
				Expected: "Valid tax type",
				Received: tax.TaxType,
				Rule:     "tax_type_validation",
				Message:  "Invalid tax type",
			})
		}

		if tax.TaxRate > 0 && tax.TaxBase > 0 {
			expectedTaxAmount := tax.TaxBase * (tax.TaxRate / 100)
			if fmt.Sprintf("%.2f", tax.TaxAmount) != fmt.Sprintf("%.2f", expectedTaxAmount) {
				errors = append(errors, model.ValidationError{
					Field:    prefix + ".taxAmount",
					Expected: fmt.Sprintf("%.2f", expectedTaxAmount),
					Received: fmt.Sprintf("%.2f", tax.TaxAmount),
					Rule:     "tax_calculation",
					Message:  "Tax amount calculation mismatch",
				})
			}
		}
	}

	return errors
}

func (v *ValidationService) validateDocumentReference(ref *model.DocumentReference) []model.ValidationError {
	var errors []model.ValidationError

	if strings.TrimSpace(ref.DocumentID) == "" {
		errors = append(errors, model.ValidationError{
			Field:    "reference.documentId",
			Expected: "Non-empty string",
			Received: ref.DocumentID,
			Rule:     "required_field",
			Message:  "Reference document ID is required",
		})
	}

	if !v.isValidDocumentType(ref.DocumentType) {
		errors = append(errors, model.ValidationError{
			Field:    "reference.documentType",
			Expected: "Valid document type",
			Received: ref.DocumentType,
			Rule:     "document_type_validation",
			Message:  "Invalid reference document type",
		})
	}

	if !v.isValidDate(ref.IssueDate) {
		errors = append(errors, model.ValidationError{
			Field:    "reference.issueDate",
			Expected: "Valid date format YYYY-MM-DD",
			Received: ref.IssueDate,
			Rule:     "date_validation",
			Message:  "Invalid reference issue date",
		})
	}

	if strings.TrimSpace(ref.Reason) == "" {
		errors = append(errors, model.ValidationError{
			Field:    "reference.reason",
			Expected: "Non-empty string",
			Received: ref.Reason,
			Rule:     "required_field",
			Message:  "Reference reason is required",
		})
	}

	return errors
}

// Funciones de validación específicas
func (v *ValidationService) isValidRUC(ruc string) bool {
	if len(ruc) != 11 {
		return false
	}
	if matched, _ := regexp.MatchString(`^\d{11}$`, ruc); !matched {
		return false
	}

	// Algoritmo de validación de RUC oficial de SUNAT
	weights := []int{5, 4, 3, 2, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 10; i++ {
		digit, _ := strconv.Atoi(string(ruc[i]))
		sum += digit * weights[i]
	}
	remainder := sum % 11
	checkDigit := 11 - remainder
	if checkDigit == 11 {
		checkDigit = 0
	} else if checkDigit == 10 {
		checkDigit = 1
	}
	lastDigit, _ := strconv.Atoi(string(ruc[10]))
	return checkDigit == lastDigit
}

func (v *ValidationService) isValidDNI(dni string) bool {
	if len(dni) != 8 {
		return false
	}
	matched, _ := regexp.MatchString(`^\d{8}$`, dni)
	return matched
}

func (v *ValidationService) isValidDocumentType(docType string) bool {
	validTypes := map[string]bool{
		"01": true, // Factura
		"03": true, // Boleta
		"07": true, // Nota de Crédito
		"08": true, // Nota de Débito
		"09": true, // Guía de Remisión
		"20": true, // Retención
		"40": true, // Percepción
	}
	return validTypes[docType]
}

func (v *ValidationService) isValidCurrency(currency string) bool {
	validCurrencies := map[string]bool{
		"PEN": true, // Sol peruano
		"USD": true, // Dólar americano
		"EUR": true, // Euro
	}
	return validCurrencies[currency]
}

func (v *ValidationService) isValidDate(dateStr string) bool {
	_, err := time.Parse("2006-01-02", dateStr)
	return err == nil
}

func (v *ValidationService) isValidUnitCode(unitCode string) bool {
	validCodes := map[string]bool{
		"NIU": true, // Unidad (bienes)
		"ZZ":  true, // Servicios
		"KGM": true, // Kilogramo
		"MTR": true, // Metro
		"LTR": true, // Litro
		"MTQ": true, // Metro cuadrado
		"MTK": true, // Metro cúbico
		"HUR": true, // Hora
		"DAY": true, // Día
		"TNE": true, // Tonelada métrica
		"GLL": true, // Galón
		"DZN": true, // Docena
		"PZA": true, // Pieza
		"SET": true, // Juego
		"CAN": true, // Lata
		"BOX": true, // Caja
	}
	return validCodes[unitCode]
}

func (v *ValidationService) isValidTaxType(taxType string) bool {
	validTypes := map[string]bool{
		"1000": true, // IGV - Impuesto General a las Ventas
		"2000": true, // ISC - Impuesto Selectivo al Consumo
		"7152": true, // ICBPER - Impuesto a las Bolsas de Plástico
		"9995": true, // Exportación
		"9997": true, // Exonerado
		"9998": true, // Inafecto
		"9996": true, // Gratuito
	}
	return validTypes[taxType]
}

// Funciones de cálculo
func (v *ValidationService) calculateSubTotal(items []model.DocumentItem) float64 {
	var total float64
	for _, item := range items {
		total += item.LineTotal
	}
	return total
}

func (v *ValidationService) calculateTotalTaxes(taxes []model.TaxTotal) float64 {
	var total float64
	for _, tax := range taxes {
		total += tax.TaxAmount
	}
	return total
}
