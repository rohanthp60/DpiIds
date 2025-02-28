package main

import (
    "fmt"
    "log"
    "os"

    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

// Path to FIFO pipe for feeding packets to Snort
const fifoPath = "/tmp/snort_fifo.pcap"

func main() {
    // Open the network interface for packet capture
    handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal("Error opening network device:", err)
    }
    defer handle.Close()

    // Open FIFO pipe for writing packets to Snort
    fifo, err := os.OpenFile(fifoPath, os.O_WRONLY, os.ModeNamedPipe)
    if err != nil {
        log.Fatal("Error opening FIFO pipe:", err)
    }
    defer fifo.Close()

    // Create a packet writer to write packets to the FIFO pipe
    packetWriter := pcap.NewWriter(fifo)
    defer packetWriter.Flush()

    fmt.Println("[INFO] Sniffing packets and forwarding to Snort...")

    // Read packets and write to Snort
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        err := packetWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
        if err != nil {
            log.Println("Error writing packet to Snort:", err)
        }
    }
}