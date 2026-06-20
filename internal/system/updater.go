package system

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// GithubRelease representa el JSON que devuelve la API de GitHub para /releases/latest
type GithubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []GithubAsset `json:"assets"`
}

type GithubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

const (
	repoOwner = "stegosec"
	repoName  = "RaptorRecon"
)

// CheckAndUpdate busca en GitHub si existe una nueva versión y reemplaza el binario en caliente.
func CheckAndUpdate(currentVersion string) error {
	fmt.Println("[*] Verificando actualizaciones de Raptor Recon...")

	// 1. Obtener información de la última release desde GitHub API
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", repoOwner, repoName)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("no se pudo conectar con GitHub: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API retornó status %d", resp.StatusCode)
	}

	var release GithubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("error al leer la respuesta de GitHub: %v", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentClean := strings.TrimPrefix(currentVersion, "v")

	if latestVersion == currentClean {
		fmt.Printf("[✓] Ya estás en la última versión de Raptor Recon (v%s).\n", currentClean)
		return nil
	}

	fmt.Printf("[!] Nueva versión detectada: v%s (Actual: v%s)\n", latestVersion, currentClean)

	// 2. Determinar el nombre esperado del asset según el OS y arquitectura
	expectedAssetName := fmt.Sprintf("raptor-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		expectedAssetName += ".exe"
	}

	var downloadURL string
	for _, asset := range release.Assets {
		// Buscamos coincidencia parcial o exacta
		if strings.Contains(asset.Name, expectedAssetName) {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no se encontró un binario compilado para %s/%s en la release v%s", runtime.GOOS, runtime.GOARCH, latestVersion)
	}

	fmt.Printf("[*] Descargando actualización: %s\n", downloadURL)

	// 3. Descargar el nuevo binario a un archivo temporal
	tmpDir := os.TempDir()
	
	// Usamos CreateTemp para mitigar G304 (Inyección de Archivo)
	out, err := os.CreateTemp(tmpDir, expectedAssetName+"-*.tmp")
	if err != nil {
		return fmt.Errorf("no se pudo crear el archivo temporal: %v", err)
	}
	tmpFile := out.Name()
	
	// El ejecutable necesita permisos +x. Gosec (G302) se queja de permisos > 0600, 
	// pero al ser un binario es estrictamente necesario, de ahí la excepción justificada.
	/* #nosec G302 */
	if err := out.Chmod(0700); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("no se pudieron asignar permisos de ejecución: %v", err)
	}

	dlResp, err := client.Get(downloadURL)
	if err != nil {
		_ = out.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("error descargando binario: %v", err)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		_ = out.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("error al descargar, código HTTP: %d", dlResp.StatusCode)
	}

	// Copiar con LimitReader (protección de cordura, max 50MB)
	lr := io.LimitReader(dlResp.Body, 50*1024*1024)
	if _, err := io.Copy(out, lr); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("error escribiendo el binario temporal: %v", err)
	}
	_ = out.Close() // Cerrar antes de reemplazar

	// 4. Reemplazo atómico del binario en ejecución
	execPath, err := os.Executable()
	if err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("no se pudo obtener la ruta del binario actual: %v", err)
	}

	if runtime.GOOS == "windows" {
		// Windows no permite sobreescribir ejecutables en uso. Lo renombramos a .old primero.
		oldPath := execPath + ".old"
		_ = os.Remove(oldPath) // Eliminar si existía de una actualización anterior
		
		if err := os.Rename(execPath, oldPath); err != nil {
			_ = os.Remove(tmpFile)
			return fmt.Errorf("error al renombrar el ejecutable actual en uso: %v", err)
		}
		
		if err := os.Rename(tmpFile, execPath); err != nil {
			// Si falla, intentamos restaurar el original
			_ = os.Rename(oldPath, execPath)
			return fmt.Errorf("error moviendo el nuevo binario a su destino: %v", err)
		}
		fmt.Printf("[✓] ¡Actualización exitosa a v%s!\n(Nota: Puedes borrar manualmente el archivo %s generado).\n", latestVersion, filepath.Base(oldPath))
	} else {
		// En Unix, os.Rename suele ser atómico y permite sobreescribir el binario en uso.
		if err := os.Rename(tmpFile, execPath); err != nil {
			_ = os.Remove(tmpFile)
			return fmt.Errorf("error reemplazando el binario: %v", err)
		}
		fmt.Printf("[✓] ¡Actualización exitosa a v%s!\n", latestVersion)
	}

	return nil
}
