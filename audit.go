package main

import (
	"fmt"
	"sync"
	"time"
)

const (
	LoginSuccess       = "success"
	LoginPasswordError = "password error"
	LoginError         = "error"
)

type LoginAudit struct {
	AccountMap     map[string]map[int64]int
	AccountMapLock sync.Mutex

	IPMap     map[string]map[int64]int
	IPMapLock sync.Mutex
}

func (a *LoginAudit) AddFailed(account, ip string) {
	if a.AccountMap == nil {
		a.AccountMap = make(map[string]map[int64]int)
	}
	if a.AccountMap == nil {
		a.IPMap = make(map[string]map[int64]int)
	}

	timestamp := time.Now().UnixNano()

	if account != "" {
		a.AccountMapLock.Lock()
		if _, ok := a.AccountMap[account]; !ok {
			a.AccountMap[account] = map[int64]int{timestamp: 1}
		} else {
			if _, ok := a.AccountMap[account][timestamp]; !ok {
				a.AccountMap[account][timestamp] = 1
			} else {
				a.AccountMap[account][timestamp]++
			}
		}
		a.AccountMapLock.Unlock()
	}

	if ip != "" {
		a.IPMapLock.Lock()
		if _, ok := a.IPMap[ip]; !ok {
			a.IPMap[ip] = map[int64]int{timestamp: 1}
		} else {
			if _, ok := a.IPMap[ip][timestamp]; !ok {
				a.IPMap[ip][timestamp] = 1
			} else {
				a.IPMap[ip][timestamp]++
			}
		}
		a.IPMapLock.Unlock()
	}
}

func (a *LoginAudit) Clear() {
	deadline := time.Now().AddDate(0, 0, -1).UnixNano()

	a.AccountMapLock.Lock()
	for k1 := range a.AccountMap {
		for k2 := range a.AccountMap[k1] {
			if k2 < deadline {
				delete(a.AccountMap[k1], k2)
			}
		}
	}
	a.AccountMapLock.Unlock()

	a.IPMapLock.Lock()
	for k1 := range a.IPMap {
		for k2 := range a.IPMap[k1] {
			if k2 < deadline {
				delete(a.IPMap[k1], k2)
			}
		}
	}
	a.IPMapLock.Unlock()
}

func (a *LoginAudit) Abnormal(account, ip string) bool {
	count := 0

	if a.AccountMap != nil {
		for _, v := range a.AccountMap[account] {
			count += v
		}
	}
	if a.IPMap != nil {
		for _, v := range a.IPMap[ip] {
			count += v
		}
	}

	if count > 10 {
		fmt.Printf("%v abnormal login, account: %v, ip: %v, count: %v\n",
			time.Now().Format("2006-01-02 15:04:05"),
			account, ip, count)
		return true
	}
	return false
}
