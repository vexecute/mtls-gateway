package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
)

type ClientAccess struct {
	ClientIP string         `json:"client_ip"`
	Services map[string]int `json:"services"` 
}

func handleError(err error) {
	if err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}

func updateFirewall(clientIP string, port int) {
	rule := fmt.Sprintf("sudo /sbin/iptables -A INPUT -p tcp -s %s --dport %d -j ACCEPT", strings.Split(clientIP, ":")[0], port)
	log.Printf("Executing command: %s", rule)

	cmd := exec.Command("bash", "-c", rule)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error updating firewall: %v, Output: %s", err, string(output))
	}

	log.Printf("Firewall updated: Allow %s access to port %d", clientIP, port)
}

func removeFirewall(clientIP string, port int) {
	rule := fmt.Sprintf("sudo /sbin/iptables -D INPUT -p tcp -s %s --dport %d -j ACCEPT", strings.Split(clientIP, ":")[0], port)
	log.Printf("Executing command to remove rule: %s", rule)

	cmd := exec.Command("bash", "-c", rule)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error removing firewall rule: %v, Output: %s", err, string(output))
	} else {
		log.Printf("Firewall rule removed: Deny %s access to port %d", clientIP, port)
	}
}

func receiveHandler(w http.ResponseWriter, r *http.Request) {
	var clientAccess ClientAccess
	err := json.NewDecoder(r.Body).Decode(&clientAccess)
	if err != nil {
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		log.Println("Error decoding request:", err)
		return
	}

	log.Printf("Received data: ClientIP=%s", clientAccess.ClientIP)

	for serviceName, port := range clientAccess.Services {
		log.Printf("Allowing client %s access to service %s on port %d", clientAccess.ClientIP, serviceName, port)
		updateFirewall(clientAccess.ClientIP, port)

	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Firewall rules updated.\n"))
}

func simpleHTTPService() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to the Gateway's Awesome 0_0 !! HTTP Service"))
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
	go simpleHTTPService()

	absPathGatewayCrt, err := filepath.Abs("certs/gateway.crt")
	handleError(err)
	absPathGatewayKey, err := filepath.Abs("certs/gateway.key")
	handleError(err)
	absPathServerCrt, err := filepath.Abs("certs/server.crt")
	handleError(err)

	serverCACert, err := ioutil.ReadFile(absPathServerCrt)
	handleError(err)

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(serverCACert)

	gatewayCert, err := tls.LoadX509KeyPair(absPathGatewayCrt, absPathGatewayKey)
	handleError(err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{gatewayCert}, 
		ClientAuth:   tls.RequireAndVerifyClientCert, 
		ClientCAs:    clientCertPool,                 
	}

	httpServer := &http.Server{
		Addr:      ":8443", 
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/receive", receiveHandler)

	fmt.Println("Gateway running on 192.168.1.6:8443")
	err = httpServer.ListenAndServeTLS(absPathGatewayCrt, absPathGatewayKey)
	if err != nil && err != http.ErrServerClosed {
		handleError(err)
	}
}
