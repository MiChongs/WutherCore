// Command xray_browser_headers records deterministic golden values for the
// Rust XHTTP browser-header compatibility tests.
//
// Formula source: Xray-core common/utils/browser.go at
// 6e3322d219140a025285ded1114fe17a5edb74d8.
package main

import (
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/cpuid/v2"
)

var safariMinor = [25]int{
	0, 0, 0, 1, 1,
	1, 2, 2, 2, 2, 3, 3, 3, 4, 4,
	4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
}

func greaseInvalid(seed int) string {
	na := []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	versions := []string{"8", "99", "24"}
	return "\"Not" + na[seed%len(na)] + "A" + na[(seed+1)%len(na)] +
		"Brand\";v=\"" + versions[seed%len(versions)] + "\""
}

func greaseOrder(seed int) []int {
	shuffle := [][3]int{
		{0, 1, 2}, {0, 2, 1}, {1, 0, 2},
		{1, 2, 0}, {2, 0, 1}, {2, 1, 0},
	}
	return shuffle[seed%len(shuffle)][:]
}

func grease(version int, brand string) string {
	values := []string{
		greaseInvalid(version),
		fmt.Sprintf("\"Chromium\";v=\"%d\"", version),
		fmt.Sprintf("\"%s\";v=\"%d\"", brand, version),
	}
	result := make([]string, len(values))
	for index, destination := range greaseOrder(version) {
		result[destination] = values[index]
	}
	return strings.Join(result, ", ")
}

func main() {
	if len(os.Args) != 4 {
		panic("usage: xray_browser_headers <seed> <unix-seconds> <local-year>")
	}
	var seed int64
	if os.Args[1] == "cpu" {
		hash := fnv.New64()
		_, _ = hash.Write([]byte(
			strconv.Itoa(cpuid.CPU.Family) +
				strconv.Itoa(cpuid.CPU.Model) +
				strconv.Itoa(cpuid.CPU.PhysicalCores) +
				strconv.Itoa(cpuid.CPU.LogicalCores) +
				strconv.Itoa(cpuid.CPU.CacheLine) +
				strconv.Itoa(cpuid.CPU.ThreadsPerCore),
		))
		seed = int64(hash.Sum64())
		fmt.Printf(
			"cpu=%d,%d,%d,%d,%d,%d seed=%d\n",
			cpuid.CPU.Family,
			cpuid.CPU.Model,
			cpuid.CPU.PhysicalCores,
			cpuid.CPU.LogicalCores,
			cpuid.CPU.CacheLine,
			cpuid.CPU.ThreadsPerCore,
			seed,
		)
	} else {
		seed, _ = strconv.ParseInt(os.Args[1], 10, 64)
	}
	nowUnix, _ := strconv.ParseInt(os.Args[2], 10, 64)
	localYear, _ := strconv.Atoi(os.Args[3])
	rng := rand.New(rand.NewSource(seed))
	random := [4]float64{
		rng.Float64(),
		rng.Float64(),
		rng.Float64(),
		rng.Float64(),
	}
	fmt.Printf("bits=%016x,%016x,%016x,%016x\n",
		math.Float64bits(random[0]),
		math.Float64bits(random[1]),
		math.Float64bits(random[2]),
		math.Float64bits(random[3]),
	)

	currentDay := nowUnix / 86400
	curlStart := time.Date(2023, 3, 20, 0, 0, 0, 0, time.UTC).Unix() / 86400
	curlDiff := currentDay - curlStart - 60 - int64(math.Floor(math.Pow(random[0], 2)*165))
	curlVersion := fmt.Sprintf("8.%d.0", curlDiff/57)

	firefoxStart := time.Date(2024, 7, 29, 0, 0, 0, 0, time.UTC).Unix() / 86400
	firefoxDiff := currentDay - firefoxStart - 25 - int64(math.Floor(math.Pow(random[1], 2)*50))
	firefoxVersion := firefoxDiff/30 + 128

	delay := int(math.Floor(math.Pow(random[2], 3) * 75))
	safariYear := localYear
	split := time.Date(safariYear, 9, 23, 0, 0, 0, 0, time.UTC).AddDate(0, 0, delay)
	now := time.Unix(nowUnix, 0)
	if now.Compare(split) < 0 {
		safariYear--
		split = time.Date(safariYear, 9, 23, 0, 0, 0, 0, time.UTC).AddDate(0, 0, delay)
	}
	safariVersion := fmt.Sprintf(
		"%d.%d",
		safariYear-1999,
		safariMinor[(now.Unix()-split.Unix())/1296000],
	)

	chromeStart := time.Date(2026, 1, 13, 0, 0, 0, 0, time.UTC).Unix() / 86400
	chromeDiff := currentDay - chromeStart - 35 - int64(math.Floor(math.Pow(random[3], 2)*105))
	chromeVersion := 144 + chromeDiff/35

	fmt.Printf("curl=curl/%s\n", curlVersion)
	fmt.Printf("firefox=Firefox/%d.0\n", firefoxVersion)
	fmt.Printf("safari=Version/%s\n", safariVersion)
	fmt.Printf("chrome=Chrome/%d.0.0.0\n", chromeVersion)
	fmt.Printf("chrome-ch=%s\n", grease(int(chromeVersion), "Google Chrome"))
	fmt.Printf("edge-ch=%s\n", grease(int(chromeVersion), "Microsoft Edge"))
}
