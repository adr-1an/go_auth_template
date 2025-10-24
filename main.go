package main

import (
	"app/routes"
	"app/utils"
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/sony/sonyflake"
)

// ===== Pretty output =====
const (
	cReset  = "\033[0m"
	cDim    = "\033[2m"
	cGreen  = "\033[32m"
	cCyan   = "\033[36m"
	cYellow = "\033[33m"
	cRed    = "\033[31m"
)

func step(tag, msg string) { // [ OK ] message
	fmt.Printf("%s[%s]%s %s\n", cGreen, tag, cReset, msg)
}
func info(msg string) {
	fmt.Printf("%s[i]%s %s\n", cCyan, cReset, msg)
}
func warn(msg string) {
	fmt.Printf("%s[!]%s %s\n", cYellow, cReset, msg)
}
func fail(msg string) {
	fmt.Printf("%s[x]%s %s\n", cRed, cReset, msg)
}

// ===== Helpers =====
func runCmd(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fail("Missing environment variable " + key)
		os.Exit(1)
	}
	return v
}

// RAM from /proc/meminfo
func parseMeminfo() (availKB, totalKB uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer func() {
		_ = f.Close()
	}()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				availKB, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
		if availKB > 0 && totalKB > 0 {
			break
		}
	}
	return
}

func humanBytes(kb uint64) string {
	b := float64(kb) * 1024
	const KB = 1024.0
	const MB = KB * 1024
	const GB = MB * 1024
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GiB", b/GB)
	case b >= MB:
		return fmt.Sprintf("%.2f MiB", b/MB)
	case b >= KB:
		return fmt.Sprintf("%.2f KiB", b/KB)
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}

type cpuTimes struct{ idle, total uint64 }

func readCPU() (cpuTimes, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}, err
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "cpu ") {
			fs := strings.Fields(ln)
			if len(fs) < 8 {
				return cpuTimes{}, fmt.Errorf("bad /proc/stat")
			}
			var vals []uint64
			for _, f := range fs[1:] {
				v, _ := strconv.ParseUint(f, 10, 64)
				vals = append(vals, v)
			}
			idle := vals[3] + vals[4] // idle + iowait
			nonIdle := vals[0] + vals[1] + vals[2] + vals[5] + vals[6] + vals[7]
			return cpuTimes{idle: idle, total: idle + nonIdle}, nil
		}
	}
	return cpuTimes{}, fmt.Errorf("CPU line not found")
}

func cpuUsagePercent(d time.Duration) string {
	a, err1 := readCPU()
	time.Sleep(d)
	b, err2 := readCPU()
	if err1 != nil || err2 != nil {
		return "unknown"
	}
	dt := float64(b.total - a.total)
	di := float64(b.idle - a.idle)
	if dt <= 0 {
		return "unknown"
	}
	return fmt.Sprintf("%.1f%%", (dt-di)/dt*100)
}

func main() {
	fmt.Println()
	info("Loading ENV")
	_ = godotenv.Load()

	// Required env vars
	port := mustEnv("APPLICATION_PORT")
	machineIDEnv := mustEnv("MACHINE_ID")
	mustEnv("ALLOWED_DOMAINS")
	mustEnv("FRONTEND_URL")
	mustEnv("APPLICATION_NAME")
	mustEnv("DB_DSN")
	mustEnv("DB_TYPE")
	mustEnv("DB_NAME")
	mustEnv("DB_USER")
	mustEnv("DB_PASS")
	mustEnv("DB_HOST")
	mustEnv("DB_PORT")
	mustEnv("SMTP_HOST")
	mustEnv("SMTP_PORT")
	mustEnv("SMTP_USERNAME")
	mustEnv("SMTP_PASSWORD")
	mustEnv("SMTP_FROM")

	// Sonyflake machine ID
	parsedMID, err := strconv.ParseUint(machineIDEnv, 16, 64)
	if err != nil {
		fail("MACHINE_ID must be hex (e.g. 01AF)")
		os.Exit(1)
	}
	sf := sonyflake.NewSonyflake(sonyflake.Settings{
		MachineID: func() (uint16, error) { return uint16(parsedMID), nil },
	})
	if sf == nil {
		fail("failed to init sonyflake")
		os.Exit(1)
	}
	step("OK", "ENV ready.")

	// DB
	info("Connecting to DB...")
	db := utils.InitDb()
	step("OK", "DB connected.")

	// Router
	info("Initializing Routes...")
	r := routes.NewRouter(db, sf)
	step("OK", "Routes ready.")

	// ===== Machine Info Block =====
	wd, _ := os.Getwd()
	hostname, _ := os.Hostname()
	kernelRelease := runCmd("uname", "-r")
	kernelVersion := runCmd("uname", "-v")
	arch := runCmd("uname", "-m")
	nodeName := runCmd("uname", "-n")

	availKB, totalKB := parseMeminfo()
	ramStr := "unknown"
	if totalKB > 0 {
		freePct := float64(availKB) / float64(totalKB) * 100
		ramStr = fmt.Sprintf("%s / %s (%.1f%% free)", humanBytes(availKB), humanBytes(totalKB), freePct)
	}
	cpuStr := cpuUsagePercent(500 * time.Millisecond)

	fmt.Println()
	fmt.Printf("%s┌──────────────────────────────── System ────────────────────────────────┐%s\n", cDim, cReset)
	fmt.Printf("  Machine ID:        %s\n", machineIDEnv)
	fmt.Printf("  Working dir:       %s\n", wd)
	fmt.Printf("  Hostname:          %s\n", hostname)
	fmt.Printf("  RAM:               %s\n", ramStr)
	fmt.Printf("  CPU Usage:         %s\n", cpuStr)
	fmt.Printf("  Kernel release:    %s\n", kernelRelease)
	fmt.Printf("  Kernel version:    %s\n", kernelVersion)
	fmt.Printf("  Architecture:      %s\n", arch)
	fmt.Printf("  Node name:         %s\n", nodeName)
	fmt.Printf("%s└────────────────────────────────────────────────────────────────────────┘%s\n\n", cDim, cReset)

	// ===== Server start + graceful shutdown =====
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	info(fmt.Sprintf("Starting server on :%s", port))
	go func() {
		time.Sleep(150 * time.Millisecond)
		step("OK", "Server listening on http://localhost:"+port+".")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fail("server: " + err.Error())
			os.Exit(1)
		}
	}()

	// Wait for SIGINT/SIGTERM
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	warn("Shutdown signal received.")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		fail("Graceful shutdown failed: " + err.Error())
	} else {
		step("OK", "Server stopped.")
	}
}
