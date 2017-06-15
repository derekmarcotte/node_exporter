// Copyright 2017 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !nomeminfo
// +build freebsd dragonfly

package collector

import (
	"fmt"
	"sync"
	"unsafe"
)

// #cgo LDFLAGS: -lkvm
// #include "kvm_bsd.h"
import "C"

type processStatus struct {
	name   string
	status string
}

/** processStatusCounts represents the count of each processStatus tuple as
 * returned by kvm_getprocs.  A collector can then safely iterate over, and
 * expose these as prometheus metrics.
 *
 * We want to do our copies and dynamic allocations on the Go side, yet iterate
 * over and access the process data structures on the C side.
 *
 * The C side is handled via processStatusCountsAdd, which refers to a
 * processStatusCounts declared on the Go side.
 */
//export processStatusCountsAdd
func processStatusCountsAdd(p *[]processStatus, name *C.char, status *C.char) {
	(*p)[processStatus{
		name:   C.GoString(name),
		status: C.GoString(status),
	}]++
}

/** kvm is the driver to interface with BSD kvm system calls to build metrics from. */
type kvm struct {
	mu     sync.Mutex
	hasErr bool
}

func NewKvm() *kvm {
	var k kvm

	k.mu.Lock()
	defer k.mu.Unlock()
	if C._kvm_init_descriptor() != 0 {
		// We don't run k.error here, it doesn't need closing.
		k.hasErr = true
	}

	return &k
}

func (k *kvm) SwapUsedPages() (value uint64, err error) {
	if k.hasErr {
		return 0, fmt.Errorf("couldn't get kvm swap used pages")
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if C._kvm_swap_used_pages((*C.uint64_t)(&value)) != 0 {
		k.error()
		return 0, fmt.Errorf("couldn't get kvm swap used pages")
	}

	return value, nil
}

func (k *kvm) ProcessStatusCounts() (p []processStatus, err error) {
	if k.hasErr {
		return nil, fmt.Errorf("couldn't get kvm process count")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	p = make(map[processStatus]int)
	if C._kvm_get_procstats(unsafe.Pointer(&p)) != 0 {
		k.error()
		return nil, fmt.Errorf("couldn't get kvm process count")
	}

	return p, nil
}

func (k *kvm) error() {
	// Called only from within a mutex.
	k.hasErr = true
	C._kvm_close()
}
