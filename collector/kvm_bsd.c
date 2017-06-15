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
#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <paths.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/user.h>

#include "_cgo_export.h"

/* Reference to kvm descriptor, must call _kvm_init_descriptor before use,
 * should call _kvm_close when no longer needed.
 */
static kvm_t *kd = NULL;

static char *state_abbrev[] = {
	"", "START", "RUN", "SLEEP", "STOP", "ZOMB", "WAIT", "LOCK"
};


int _kvm_init_descriptor() {
	if (kd != NULL) {
		return -1;
	}

	kd  = kvm_open(NULL, _PATH_DEVNULL, NULL, O_RDONLY, NULL);
	if (kd == NULL) {
		return -1;
	}

	return 0;
}

int _kvm_close() {
	int ret;

	if (kd == NULL) {
		return -1;
	}
	
	ret = kvm_close(kd);
	kd = NULL;

	return ret;
}

int _kvm_swap_used_pages(uint64_t *out) {
	const int total_only = 1; // from kvm_getswapinfo(3)
	struct kvm_swap current;

	if (kd == NULL) {
		return -1;
	}

	if (kvm_getswapinfo(kd, &current, total_only, 0) == -1) {
		return -1;
	}

	*out = current.ksw_used;

	return 0;
}

int _kvm_get_procstats(void *p) {
	struct kinfo_proc *kp;
	int nentries = -1;

	int i;
	char *name;
	char *status;

	if (kd == NULL) {
		return -1;
	}
	
	kp = kvm_getprocs(kd, KERN_PROC_PROC, 0, &nentries);
	if ((kp == NULL && nentries > 0) || (kp != NULL && nentries < 0)) {
		return -1;
	}

	for (i = nentries; --i >= 0; ++kp) {
		// TODO: Add more detail to the status
		name = kp->ki_comm;
		status = state_abbrev[kp->ki_stat];
		processStatusCountsAdd(p, kp->ki_comm, status);
	}

	return 0;
}
