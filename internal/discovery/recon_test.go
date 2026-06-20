package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDiscoverLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Probar resolviendo localhost o 127.0.0.1 con puertos de discovery mínimos
	probePorts := []int{80, 443}
	ch, err := Discover(ctx, "127.0.0.1/32", probePorts, 1, 100*time.Millisecond, nil, nil)
	if err != nil {
		t.Fatalf("Error en Discover: %v", err)
	}

	var ips []string
	for ip := range ch {
		ips = append(ips, ip)
	}

	// 127.0.0.1 normalmente no responderá en entornos de testing vacíos,
	// por lo que ips probablemente esté vacío. Eso es correcto.
	// Pero probamos que se procesa sin errores y cierra el canal.
	t.Logf("IPs vivas encontradas: %v", ips)
}

func TestGenerateIPs(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.0.0.1/30")
	if err != nil {
		t.Fatalf("Error parsing CIDR: %v", err)
	}

	ipChan := generateIPs(context.Background(), ipnet)
	var ips []string
	for ip := range ipChan {
		ips = append(ips, ip)
	}

	// /30 excluye la dirección de red (.0), pero mantiene .3 en este algoritmo simple
	// ya que solo excluye .0 y .255.
	// Por tanto, debe contener 10.0.0.1, 10.0.0.2 y 10.0.0.3.
	if len(ips) != 3 {
		t.Errorf("Esperaba 3 IPs, obtuve %d: %v", len(ips), ips)
	}
}
