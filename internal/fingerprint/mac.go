package fingerprint

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed oui.json
var ouiJSON []byte

var vendorMap map[string]string

func init() {
	vendorMap = make(map[string]string)
	if err := json.Unmarshal(ouiJSON, &vendorMap); err != nil {
		panic("Failed to parse embedded oui.json: " + err.Error())
	}
}

// LookupVendor extrae los primeros 3 bytes de la MAC y busca el fabricante en la base embebida.
func LookupVendor(mac string) string {
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, "-", ":")
	parts := strings.Split(mac, ":")
	
	if len(parts) >= 3 {
		prefix := parts[0] + ":" + parts[1] + ":" + parts[2]
		if vendor, ok := vendorMap[prefix]; ok {
			return vendor
		}
	}
	return ""
}
