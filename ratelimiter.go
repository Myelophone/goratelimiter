package goratelimiter

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

var rateLimit, _ = strconv.Atoi(getenv("RATE_LIMIT", "60"))
var authLimit, _ = strconv.Atoi(getenv("AUTH_LIMIT", "10"))

var (
	maxRequests     = rateLimit
	perMinutePeriod = 1 * time.Minute
)

var (
	ipRequestsCounts = make(map[string]int)
	mutex            = &sync.Mutex{}
)

// getMacAddr gets the MAC hardware
// address of the host machine
func getMacAddr() (addr string) {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if !bytes.Equal(i.HardwareAddr, nil) {
				addr = i.HardwareAddr.String()
				break
			}
		}
	}
	return addr
}

func RateLimiter(c *gin.Context) {
	ip := c.ClientIP() + getMacAddr()
	mutex.Lock()
	defer mutex.Unlock()
	count := ipRequestsCounts[ip]
	var limiter = maxRequests
	if (strings.Contains(c.Request.URL.Path, "/auth/")) || (c.Request.Method == "POST") {
		limiter = authLimit
	}
	if count >= limiter {
		c.AbortWithStatus(http.StatusTooManyRequests)
		// add json response
		return
	}

	ipRequestsCounts[ip] = count + 1
	time.AfterFunc(perMinutePeriod, func() {
		mutex.Lock()
		defer mutex.Unlock()

		ipRequestsCounts[ip] = ipRequestsCounts[ip] - 1
	})

	c.Next()
}
