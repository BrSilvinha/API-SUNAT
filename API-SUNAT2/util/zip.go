package util

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ZipXMLFile empaqueta un archivo XML en un ZIP con el mismo nombre base
func ZipXMLFile(xmlPath string) (string, error) {
	// Verificar que el archivo XML existe
	if _, err := os.Stat(xmlPath); os.IsNotExist(err) {
		return "", fmt.Errorf("XML file does not exist: %s", xmlPath)
	}

	// Generar ruta del ZIP
	zipPath := xmlPath[:len(xmlPath)-4] + ".zip" // reemplaza .xml por .zip

	// Crear archivo ZIP
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create ZIP file: %v", err)
	}
	defer zipFile.Close()

	// Crear writer ZIP
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Abrir archivo XML
	xmlFile, err := os.Open(xmlPath)
	if err != nil {
		return "", fmt.Errorf("failed to open XML file: %v", err)
	}
	defer xmlFile.Close()

	// Obtener información del archivo XML
	xmlInfo, err := xmlFile.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get XML file info: %v", err)
	}

	// Crear header para el archivo en el ZIP
	header, err := zip.FileInfoHeader(xmlInfo)
	if err != nil {
		return "", fmt.Errorf("failed to create ZIP header: %v", err)
	}

	// Configurar el nombre del archivo en el ZIP
	header.Name = filepath.Base(xmlPath)
	header.Method = zip.Deflate // Usar compresión

	// Crear writer para el archivo dentro del ZIP
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return "", fmt.Errorf("failed to create ZIP entry: %v", err)
	}

	// Copiar contenido del XML al ZIP
	_, err = io.Copy(writer, xmlFile)
	if err != nil {
		return "", fmt.Errorf("failed to copy XML content to ZIP: %v", err)
	}

	return zipPath, nil
}

// ZipMultipleFiles empaqueta múltiples archivos en un ZIP
func ZipMultipleFiles(files []string, zipPath string) error {
	// Crear archivo ZIP
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create ZIP file: %v", err)
	}
	defer zipFile.Close()

	// Crear writer ZIP
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Agregar cada archivo al ZIP
	for _, filePath := range files {
		if err := addFileToZip(zipWriter, filePath); err != nil {
			return fmt.Errorf("failed to add file %s to ZIP: %v", filePath, err)
		}
	}

	return nil
}

// addFileToZip agrega un archivo individual al ZIP
func addFileToZip(zipWriter *zip.Writer, filePath string) error {
	// Abrir archivo
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Obtener información del archivo
	info, err := file.Stat()
	if err != nil {
		return err
	}

	// Crear header
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	// Configurar nombre y compresión
	header.Name = filepath.Base(filePath)
	header.Method = zip.Deflate

	// Crear writer para el archivo
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	// Copiar contenido
	_, err = io.Copy(writer, file)
	return err
}

// ValidateZipFile verifica que un archivo ZIP sea válido
func ValidateZipFile(zipPath string) error {
	// Abrir archivo ZIP para lectura
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open ZIP file: %v", err)
	}
	defer reader.Close()

	// Verificar que tiene al menos un archivo
	if len(reader.File) == 0 {
		return fmt.Errorf("ZIP file is empty")
	}

	// Verificar cada archivo en el ZIP
	for _, file := range reader.File {
		// Abrir archivo dentro del ZIP
		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file %s in ZIP: %v", file.Name, err)
		}
		rc.Close()
	}

	return nil
}
