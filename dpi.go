package main

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"os"
	"time"


	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ThreatLevel represents the severity of a potential network threat
type ThreatLevel int

const (
	LowThreat ThreatLevel = iota
	MediumThreat
	HighThreat
	CriticalThreat
)

// ThreatSignature defines a structure for identifying potential threats
type ThreatSignature struct {
	Pattern     *regexp.Regexp
	Description string
	Severity    ThreatLevel
}

// Flow represents a network flow (source IP, destination IP, ports, etc.)
type Flow struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	Packets  int
	Bytes    int
}

const logFilePath = "/home/vm3/Codes/DpiIds/threat_log.txt"

// Function to log threats to a file
func logToFile(threatLevel, threatType, attackerIP, affectedIP string) {
    // Open the file in append mode, create if it doesn't exist
    file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Println("Error opening log file:", err)
        return
    }
    defer file.Close()

    // Create a logger
    logger := log.New(file, "", 0)

    // Get the current timestamp
    timestamp := time.Now().Format("2006-01-02 15:04:05")

    // Log the message
    logEntry := fmt.Sprintf("[%s] %s threat detected (%s) from IP: %s -> IP: %s\n",
        timestamp, threatLevel, threatType, attackerIP, affectedIP)

    // Write to file
    logger.Println(logEntry)
}

// predefinedThreats is a list of known threat signatures
var predefinedThreats = []ThreatSignature{
	{
		// Added additional functions like passthru, popen, and proc_open.
		Pattern:     regexp.MustCompile(`(?i)\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(`),
		Description: "Potential Remote Code Execution",
		Severity:    CriticalThreat,
	},
	{
		// Expanded SQL injection detection:
		// - Captures common commands like DROP, UNION, SELECT, INSERT, UPDATE, DELETE.
		// - Includes patterns for boolean-based injections such as ' OR '1'='1.
		Pattern: regexp.MustCompile(`(?i)\b(?:drop\s+table|union\s+select|select\s+\*\s+from|insert\s+into|update\s+\S+\s+set|delete\s+from|(?:(?:or|and)\s+(?:'|")?1(?:'|")?\s*=\s*(?:'|")?1(?:'|")?))\b`),
		Description: "Potential SQL Injection",
		Severity:    HighThreat,
	},
	{
		// Expanded XSS detection with additional event handlers.
		Pattern:     regexp.MustCompile(`(?i)(<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=)`),
		Description: "Potential Cross-Site Scripting (XSS)",
		Severity:    HighThreat,
	},
	{
		// Added additional common network tools and ensured a word boundary.
		Pattern:     regexp.MustCompile(`(?i)\b(?:wget|curl|netcat|ncat|scp|sftp)\b(?:\s+|$)`),
		Description: "Potential Malicious Network Tool Usage",
		Severity:    MediumThreat,
	},
	{
		// Tightened word boundaries and allowed for minor variations (e.g. fast-flux written with a hyphen or space).
		Pattern:     regexp.MustCompile(`(?i)\b(?:\.onion|torproject|\.xyz|fast[-\s]?flux|dns\s*[-]?\s*tunnel)\b`),
		Description: "DNS Tunnel",
		Severity:    MediumThreat,
	},
	{
		// Added a few extra malware names for broader coverage.
		Pattern:     regexp.MustCompile(`(?i)\b(?:emotet|wannacry|cobaltstrike|mirai|botnet|trickbot|locky)\b`),
		Description: "Malware Traffic",
		Severity:    HighThreat,
	},
	{
		// Included "beacon" and allowed flexible whitespace around the colon.
		Pattern:     regexp.MustCompile(`(?i)\b(?:pingback|heartbeat|keepalive|beacon|user-agent\s*:\s*malware)\b`),
		Description: "C2 Traffic",
		Severity:    MediumThreat,
	},
	{
		// Included a variant for detecting exit nodes in addition to hidden services.
		Pattern:     regexp.MustCompile(`(?i)\b(?:tor\s+network\s+detected|hidden\s+service\s+access|tor\s+exit\s+node)\b`),
		Description: "Tor Traffic",
		Severity:    HighThreat,
	},
	{
		// Expanded ransomware variants.
		Pattern:     regexp.MustCompile(`(?i)\b(?:wannacry|wnry|wannadecryptor|locky|cryptolocker|ryuk)\b`),
		Description: "Ransomware",
		Severity:    CriticalThreat,
	},
	{
		// Added a few more Nmap scan types.
		Pattern:     regexp.MustCompile(`(?i)\b(?:nmap\s+scan\s+detected|syn\s+scan|null\s+scan|xmas\s+scan|ack\s+scan|fin\s+scan)\b`),
		Description: "Nmap Scan",
		Severity:    MediumThreat,
	},
}



// flowMap tracks network flows for behavioral analysis
var flowMap = make(map[string]*Flow)

func main() {
	handle, err := pcap.OpenLive("enp0s3", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device: %v", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("ip")
	if err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Starting Deep Packet Inspection...")

	for packet := range packetSource.Packets() {
		threatLevel, threatType, attackerIP, affectedIP := analyzeThreat(packet)
		if threatLevel > LowThreat {
			logToFile(threatLevelToString(threatLevel), threatType, attackerIP, affectedIP)
		}
	}
}



func analyzeThreat(packet gopacket.Packet) (ThreatLevel, string, string, string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return LowThreat, "", "", ""
	}
	ipPacket, _ := ipLayer.(*layers.IPv4)

	var srcPort, dstPort uint16
	var protocol string
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcpPacket.SrcPort)
		dstPort = uint16(tcpPacket.DstPort)
		protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udpPacket, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udpPacket.SrcPort)
		dstPort = uint16(udpPacket.DstPort)
		protocol = "UDP"
	}

	flowKey := fmt.Sprintf("%s:%d-%s:%d", ipPacket.SrcIP, srcPort, ipPacket.DstIP, dstPort)
	if flow, exists := flowMap[flowKey]; exists {
		flow.Packets++
		flow.Bytes += len(packet.Data())
	} else {
		flowMap[flowKey] = &Flow{
			SrcIP:    ipPacket.SrcIP,
			DstIP:    ipPacket.DstIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: protocol,
			Packets:  1,
			Bytes:    len(packet.Data()),
		}
	}

	payloadStr := string(packet.Data())
	threatLevel, threatType := analyzePredefinedThreats(payloadStr)

	return threatLevel, threatType, ipPacket.DstIP.String(), ipPacket.SrcIP.String()
}

func analyzePredefinedThreats(payload string) (ThreatLevel, string) {
	maxThreatLevel := LowThreat
	threatType := ""

	for _, threat := range predefinedThreats {
		if threat.Pattern.MatchString(payload) {
			if threat.Severity > maxThreatLevel {
				maxThreatLevel = threat.Severity
				threatType = threat.Description
			}
		}
	}

	return maxThreatLevel, threatType
}

func threatLevelToString(level ThreatLevel) string {
	switch level {
	case LowThreat:
		return "Low"
	case MediumThreat:
		return "Medium"
	case HighThreat:
		return "High"
	case CriticalThreat:
		return "Critical"
	default:
		return "Unknown"
	}
}
