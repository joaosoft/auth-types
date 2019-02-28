package jwt

import (
	"fmt"
	"strconv"
	"time"
)

type claims map[string]interface{}

func (c claims) Validate() bool {
	now := time.Now().Unix()

	if c.checkExpiredAt(now) && c.checkIssuedAt(now) && c.checkNotBefore(now) {
		return true
	}

	return false
}

func (c claims) checkExpiredAt(now int64) bool {
	if value, ok := c[constClaimsExpiredAtKey]; ok {
		intValue, err := strconv.ParseInt(fmt.Sprintf("%+v", value), 10, 64)
		if err != nil {
			return false
		}

		if intValue >= now {
			return false
		}
	}

	return true
}

func (c claims) checkIssuedAt(now int64) bool {
	if value, ok := c[constClaimsIssuedAtKey]; ok {
		intValue, err := strconv.ParseInt(fmt.Sprintf("%+v", value), 10, 64)
		if err != nil {
			return false
		}

		if intValue >= now {
			return false
		}
	}
	return true
}

func (c claims) checkNotBefore(now int64) bool {
	if value, ok := c[constClaimsNotBeforeKey]; ok {
		intValue, err := strconv.ParseInt(fmt.Sprintf("%+v", value), 10, 64)
		if err != nil {
			return false
		}

		if intValue < now {
			return false
		}
	}
	return true
}
