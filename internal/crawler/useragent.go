package crawler

import (
	"fmt"
	"math/rand"
	"strings"
)

var uaGens = []func() string{
	genFirefoxUA,
	genChromeUA,
	genEdgeUA,
	genOperaUA,
}

var uaGensMobile = []func() string{
	genMobilePixel7UA,
	genMobilePixel6UA,
	genMobilePixel5UA,
	genMobilePixel4UA,
	genMobileNexus10UA,
}

// RandomUserAgent returns a random desktop browser user-agent string.
func RandomUserAgent() string {
	return uaGens[rand.Intn(len(uaGens))]()
}

// RandomMobileUserAgent returns a random mobile browser user-agent string.
func RandomMobileUserAgent() string {
	return uaGensMobile[rand.Intn(len(uaGensMobile))]()
}

var ffVersions = []float32{
	102.0, 103.0, 104.0, 105.0, 106.0, 107.0, 108.0,
	109.0, 110.0, 111.0, 112.0, 113.0,
}

var chromeVersions = []string{
	"102.0.5005.115", "103.0.5060.53", "103.0.5060.66", "103.0.5060.114",
	"103.0.5060.134", "104.0.5112.79", "104.0.5112.80", "104.0.5112.81",
	"104.0.5112.101", "104.0.5112.102", "105.0.5195.52", "105.0.5195.53",
	"105.0.5195.54", "105.0.5195.102", "105.0.5195.125", "105.0.5195.126",
	"105.0.5195.127", "106.0.5249.61", "106.0.5249.62", "106.0.5249.91",
	"106.0.5249.103", "106.0.5249.119", "107.0.5304.62", "107.0.5304.63",
	"107.0.5304.68", "107.0.5304.87", "107.0.5304.88", "107.0.5304.106",
	"107.0.5304.107", "107.0.5304.110", "107.0.5304.121", "107.0.5304.122",
	"108.0.5359.71", "108.0.5359.72", "108.0.5359.94", "108.0.5359.95",
	"108.0.5359.98", "108.0.5359.99", "108.0.5359.124", "108.0.5359.125",
	"109.0.5414.74", "109.0.5414.75", "109.0.5414.87", "109.0.5414.119",
	"109.0.5414.120", "110.0.5481.77", "110.0.5481.78", "110.0.5481.96",
	"110.0.5481.97", "110.0.5481.100", "110.0.5481.104", "110.0.5481.177",
	"110.0.5481.178", "109.0.5414.129", "111.0.5563.64", "111.0.5563.65",
	"111.0.5563.110", "111.0.5563.111", "111.0.5563.146", "111.0.5563.147",
	"112.0.5615.49", "112.0.5615.50", "112.0.5615.86", "112.0.5615.87",
	"112.0.5615.121", "112.0.5615.137", "112.0.5615.138", "112.0.5615.165",
	"113.0.5672.63", "113.0.5672.64", "113.0.5672.92", "113.0.5672.93",
}

var edgeVersions = []string{
	"103.0.0.0,103.0.1264.37", "104.0.0.0,104.0.1293.47",
	"105.0.0.0,105.0.1343.25", "106.0.0.0,106.0.1370.34",
	"107.0.0.0,107.0.1418.24", "108.0.0.0,108.0.1462.42",
	"109.0.0.0,109.0.1518.49", "110.0.0.0,110.0.1587.41",
	"111.0.0.0,111.0.1661.41", "112.0.0.0,112.0.1722.34",
	"113.0.0.0,113.0.1774.3",
}

var operaVersions = []string{
	"110.0.5449.0,96.0.4640.0", "110.0.5464.2,96.0.4653.0",
	"110.0.5464.2,96.0.4660.0", "110.0.5481.30,96.0.4674.0",
	"110.0.5481.30,96.0.4691.0", "110.0.5481.30,96.0.4693.12",
	"110.0.5481.77,96.0.4693.16", "110.0.5481.100,96.0.4693.20",
	"110.0.5481.178,96.0.4693.31", "110.0.5481.178,96.0.4693.50",
	"110.0.5481.192,96.0.4693.80", "111.0.5532.2,97.0.4711.0",
	"111.0.5532.2,97.0.4704.0", "111.0.5532.2,97.0.4697.0",
	"111.0.5562.0,97.0.4718.0", "111.0.5563.19,97.0.4719.4",
	"111.0.5563.19,97.0.4719.11", "111.0.5563.41,97.0.4719.17",
	"111.0.5563.65,97.0.4719.26", "111.0.5563.65,97.0.4719.28",
	"111.0.5563.111,97.0.4719.43", "111.0.5563.147,97.0.4719.63",
	"111.0.5563.147,97.0.4719.83", "112.0.5596.2,98.0.4756.0",
	"112.0.5596.2,98.0.4746.0", "112.0.5615.20,98.0.4759.1",
	"112.0.5615.50,98.0.4759.3", "112.0.5615.87,98.0.4759.6",
	"112.0.5615.165,98.0.4759.15", "112.0.5615.165,98.0.4759.21",
	"112.0.5615.165,98.0.4759.39",
}

var pixel7AndroidVersions = []string{"13"}
var pixel6AndroidVersions = []string{"12", "13"}
var pixel5AndroidVersions = []string{"11", "12", "13"}
var pixel4AndroidVersions = []string{"10", "11", "12", "13"}
var nexus10AndroidVersions = []string{"4.4.2", "4.4.4", "5.0", "5.0.1", "5.0.2", "5.1", "5.1.1"}

var nexus10Builds = []string{
	"LMY49M", "LMY49J", "LMY49I", "LMY49H", "LMY49G", "LMY49F",
	"LMY48Z", "LMY48X", "LMY48T", "LMY48M", "LMY48I", "LMY47V",
	"LMY47D", "LRX22G", "LRX22C", "LRX21P", "KTU84P", "KTU84L",
	"KOT49H", "KOT49E", "KRT16S", "JWR66Y", "JWR66V", "JWR66N",
	"JDQ39", "JOP40F", "JOP40D", "JOP40C",
}

var osStrings = []string{
	"Macintosh; Intel Mac OS X 10_13", "Macintosh; Intel Mac OS X 10_13_6",
	"Macintosh; Intel Mac OS X 10_14", "Macintosh; Intel Mac OS X 10_14_6",
	"Macintosh; Intel Mac OS X 10_15", "Macintosh; Intel Mac OS X 10_15_7",
	"Macintosh; Intel Mac OS X 11_0", "Macintosh; Intel Mac OS X 11_2",
	"Macintosh; Intel Mac OS X 11_6", "Macintosh; Intel Mac OS X 11_7",
	"Macintosh; Intel Mac OS X 12_0", "Macintosh; Intel Mac OS X 12_6",
	"Macintosh; Intel Mac OS X 13_0", "Macintosh; Intel Mac OS X 13_3_1",
	"Windows NT 10.0; Win64; x64", "Windows NT 5.1",
	"Windows NT 6.1; WOW64", "Windows NT 6.1; Win64; x64",
	"X11; Linux x86_64",
}

func genFirefoxUA() string {
	v := ffVersions[rand.Intn(len(ffVersions))]
	o := osStrings[rand.Intn(len(osStrings))]
	return fmt.Sprintf("Mozilla/5.0 (%s; rv:%.1f) Gecko/20100101 Firefox/%.1f", o, v, v)
}

func genChromeUA() string {
	v := chromeVersions[rand.Intn(len(chromeVersions))]
	o := osStrings[rand.Intn(len(osStrings))]
	return fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", o, v)
}

func genEdgeUA() string {
	pair := edgeVersions[rand.Intn(len(edgeVersions))]
	parts := strings.Split(pair, ",")
	o := osStrings[rand.Intn(len(osStrings))]
	return fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36 Edg/%s", o, parts[0], parts[1])
}

func genOperaUA() string {
	pair := operaVersions[rand.Intn(len(operaVersions))]
	parts := strings.Split(pair, ",")
	o := osStrings[rand.Intn(len(osStrings))]
	return fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36 OPR/%s", o, parts[0], parts[1])
}

func genMobilePixel7UA() string {
	a := pixel7AndroidVersions[rand.Intn(len(pixel7AndroidVersions))]
	c := chromeVersions[rand.Intn(len(chromeVersions))]
	return fmt.Sprintf("Mozilla/5.0 (Linux; Android %s; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", a, c)
}

func genMobilePixel6UA() string {
	a := pixel6AndroidVersions[rand.Intn(len(pixel6AndroidVersions))]
	c := chromeVersions[rand.Intn(len(chromeVersions))]
	return fmt.Sprintf("Mozilla/5.0 (Linux; Android %s; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", a, c)
}

func genMobilePixel5UA() string {
	a := pixel5AndroidVersions[rand.Intn(len(pixel5AndroidVersions))]
	c := chromeVersions[rand.Intn(len(chromeVersions))]
	return fmt.Sprintf("Mozilla/5.0 (Linux; Android %s; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", a, c)
}

func genMobilePixel4UA() string {
	a := pixel4AndroidVersions[rand.Intn(len(pixel4AndroidVersions))]
	c := chromeVersions[rand.Intn(len(chromeVersions))]
	return fmt.Sprintf("Mozilla/5.0 (Linux; Android %s; Pixel 4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", a, c)
}

func genMobileNexus10UA() string {
	b := nexus10Builds[rand.Intn(len(nexus10Builds))]
	a := nexus10AndroidVersions[rand.Intn(len(nexus10AndroidVersions))]
	c := chromeVersions[rand.Intn(len(chromeVersions))]
	return fmt.Sprintf("Mozilla/5.0 (Linux; Android %s; Nexus 10 Build/%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", a, b, c)
}
