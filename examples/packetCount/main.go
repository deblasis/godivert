package main

import (
	"context"
	"fmt"
	"time"

	"github.com/deblasis/godivert"
	"github.com/deblasis/godivert/header"
)

var icmpv4, icmpv6, udp, tcp, unknown, served uint

func checkPacket(wd *godivert.WinDivertHandle, packetChan <-chan *godivert.Packet) {
	for packet := range packetChan {
		countPacket(packet)
		wd.Send(packet)
	}
}

func countPacket(packet *godivert.Packet) {
	served++
	switch packet.NextHeaderType() {
	case header.ICMPv4:
		icmpv4++
	case header.ICMPv6:
		icmpv6++
	case header.TCP:
		tcp++
	case header.UDP:
		udp++
	default:
		unknown++
	}
}

func main() {
	winDivert, err := godivert.NewWinDivertHandle("true")
	if err != nil {
		panic(err)
	}

	fmt.Println("Starting")

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	packetChan, err := winDivert.Packets(ctx)
	if err != nil {
		panic(err)
	}
	defer winDivert.Close()

	n := 50
	for i := 0; i < n; i++ {
		go checkPacket(winDivert, packetChan)
	}

	<-ctx.Done() // Wait for context to be done

	fmt.Println("Stopping...")
	fmt.Printf("Served: %d packets\n", served)
	fmt.Printf("ICMPv4=%d ICMPv6=%d UDP=%d TCP=%d Unknown=%d", icmpv4, icmpv6, udp, tcp, unknown)
}
