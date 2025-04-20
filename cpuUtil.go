package main

import (
	"fmt"
	"os"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
)

func main() {
	fmt.Println("Starting CPU usage monitoring...")
	for {

		percentages, err := cpu.Percent(time.Second, false)
		if err != nil {
			fmt.Println("Error getting CPU usage:", err)
			continue
		}

		usage := fmt.Sprintf("%.2f", percentages[0])
		fmt.Println("CPU Usage:", usage)

		err = os.WriteFile("/home/vm3/Codes/DpiIds/cpu_usage.txt", []byte(usage), 0644)
		if err != nil {
			fmt.Println("Error writing to file:", err)
		}
	}
}
