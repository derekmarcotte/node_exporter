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

#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/user.h>

#include "kvm_bsd.h"

static char *state_abbrev[] = {
	"", "START", "RUN", "SLEEP", "STOP", "ZOMB", "WAIT", "LOCK"
};


int _kvm_open(kvm_t **out) {
	if ((*out) != NULL) {
		return -1;
	}

	(*out) = kvm_open(NULL, _PATH_DEVNULL, NULL, O_RDONLY, NULL);
	if ((*out) == NULL) {
		return -1;
	}

	return 0;
}

int _kvm_close(kvm_t **kd) {
	int ret;

	if ((*kd) == NULL) {
		return -1;
	}
	
	ret = kvm_close((*kd));
	(*kd) = NULL;

	return ret;
}

int _kvm_swap_used_pages(kvm_t *kd, uint64_t *out) {
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

/** _kvm_get_procstats populates out with an array of proc_state_t of
 * nentries elments.  It mallocs the pointer returned in out, but does not
 * free the space.  The space is owned by the calling function.
 */
int _kvm_get_procstats(kvm_t *kd, proc_state_t **out, int *nentries) {
	struct kinfo_proc *kp;
	int i;

	if (kd == NULL) {
		return -1;
	}

	if ((*out) != NULL) {
		// Out must be uninitialized.
		return -1;
	}
	
	(*nentries) = -1;

	kp = kvm_getprocs(kd, KERN_PROC_PROC, 0, nentries);
	if ((kp == NULL && (*nentries) > 0) || (kp != NULL && (*nentries) < 0)) {
		return -1;
	}
	if ((*nentries) == 0) {
		return 0;
	}

	(*out) = malloc(sizeof(proc_state_t) * (*nentries));
	if ((*out) == NULL) {
		return -1;
	}

	for (i = 0; i < (*nentries); i++, ++kp) {
		// TODO: Add more detail to the status
		(*out)[i].name = kp->ki_comm;
		(*out)[i].status = state_abbrev[kp->ki_stat];
	}

	return 0;
}
