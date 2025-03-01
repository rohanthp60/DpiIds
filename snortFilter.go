package main

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "sync"
    "syscall"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/pcapgo"
)


type NetworkUsage struct {
    MAC       string `json:"mac"`
    BytesSent uint64 `json:"bytes_sent"`
    BytesRecv uint64 `json:"bytes_received"`
}


var macData = make(map[string]*NetworkUsage)


var mu sync.Mutex


const jsonFilePath = "/tmp/network_usage.json"


func getFifoPath() string {
    return "/home/vm3/Codes/DpiIds/snort_fifo.pcap"
}


func saveDataPeriodically() {
    for {
        time.Sleep(10 * time.Second) 

        mu.Lock()
        var file *os.File
        var err error

        if _, err = os.Stat(jsonFilePath); os.IsNotExist(err) {
            file, err = os.Create(jsonFilePath)
            if err != nil {
            log.Println("Error creating JSON file:", err)
            mu.Unlock()
            continue
            }
        } else {
            file, err = os.OpenFile(jsonFilePath, os.O_WRONLY|os.O_TRUNC, 0666)
            if err != nil {
            log.Println("Error opening JSON file:", err)
            mu.Unlock()
            continue
            }
        }

        encoder := json.NewEncoder(file)
        encoder.SetIndent("", "  ") 

        err = encoder.Encode(macData)
        if err != nil {
            log.Println("Error writing JSON:", err)
        }

        file.Close()
        mu.Unlock()
    }
}


func homePacket(packet gopacket.Packet) bool {
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        ip, _ := ipLayer.(*layers.IPv4)
        if ip != nil {
            srcIP := ip.SrcIP.String()
            dstIP := ip.DstIP.String()
            if srcIP[:7] == "10.0.2." && dstIP[:7] == "10.0.2." {
                return true
            }
        }
    }
    return false
}




func trackData(packet gopacket.Packet) {
    ethLayer := packet.Layer(layers.LayerTypeEthernet)
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ethLayer != nil && ipLayer != nil {
        eth, _ := ethLayer.(*layers.Ethernet)
        ip, _ := ipLayer.(*layers.IPv4)
        if eth != nil && ip != nil {
            srcIP := ip.SrcIP.String()
            dstIP := ip.DstIP.String()
            packetSize := uint64(len(packet.Data()))

            mu.Lock()
            if srcIP[:7] == "10.0.2." {
                if _, exists := macData[eth.SrcMAC.String()]; !exists {
                    macData[eth.SrcMAC.String()] = &NetworkUsage{MAC: eth.SrcMAC.String()}
                }
                macData[eth.SrcMAC.String()].BytesSent += packetSize
            }

            if dstIP[:7] == "10.0.2." {
                if _, exists := macData[eth.DstMAC.String()]; !exists {
                    macData[eth.DstMAC.String()] = &NetworkUsage{MAC: eth.DstMAC.String()}
                }
                macData[eth.DstMAC.String()].BytesRecv += packetSize
            }
            mu.Unlock()
        }
    }
}

func preloadMacData() {
    file, err := os.Open(jsonFilePath)
    if err != nil {
        if os.IsNotExist(err) {
            return 
        }
        log.Println("Error opening JSON file:", err)
        return
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    err = decoder.Decode(&macData)
    if err != nil {
        log.Println("Error decoding JSON data:", err)
    }
}

func main() {
    preloadMacData()

    fifoPath := getFifoPath()

    go saveDataPeriodically()


    _, err := os.Stat(fifoPath)
    if os.IsNotExist(err) {
        err := syscall.Mkfifo(fifoPath, 0666)
        if err != nil {
            log.Fatal("Error creating FIFO pipe:", err)
        }
    }


    handle, err := pcap.OpenLive("enp0s3", 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal("Error opening network device:", err)
    }
    defer handle.Close()

 
    fifo, err := os.OpenFile(fifoPath, os.O_WRONLY, os.ModeNamedPipe)
    if err != nil {
        log.Fatal("Error opening FIFO pipe:", err)
    }
    defer fifo.Close()

    // Create pcap writer
    packetWriter := pcapgo.NewWriter(fifo)
    err = packetWriter.WriteFileHeader(1600, handle.LinkType())
    if err != nil {
        log.Fatal("Error writing file header to FIFO:", err)
    }

    fmt.Println("[INFO] Sniffing packets and forwarding to Snort...")

    // Capture packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        if !homePacket(packet) {
            continue
        }

        trackData(packet) // Update MAC data usage

        if packet.Metadata() == nil {
            log.Println("Warning: Packet metadata is nil, skipping")
            continue
        }

        captureInfo := gopacket.CaptureInfo{
            Length:        packet.Metadata().CaptureInfo.Length,
            CaptureLength: packet.Metadata().CaptureInfo.CaptureLength,
        }

        err := packetWriter.WritePacket(captureInfo, packet.Data())
        if err != nil {
            log.Println("Error writing packet to FIFO:", err)
        }
    }
}
