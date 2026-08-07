package access

import (
	"testing"
	"time"
)

func at(seconds int) time.Time {
	return time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC).Add(time.Duration(seconds) * time.Second)
}

func TestAThrottleLocksAfterTheConfiguredNumberOfFailures(t *testing.T) {
	th := &Throttle{Max: 3, Window: 60 * time.Second}

	if th.Allow("ada", at(0)).Locked {
		t.Fatal("a name with no failures is locked")
	}
	for i := 1; i <= 2; i++ {
		if verdict := th.Failed("ada", at(i)); verdict.Locked {
			t.Fatalf("locked after %d of 3 failures", i)
		}
	}
	if verdict := th.Failed("ada", at(3)); !verdict.Locked {
		t.Fatal("not locked after the third of three failures")
	}
	if !th.Allow("ada", at(4)).Locked {
		t.Fatal("a locked name is allowed on the next attempt")
	}
}

func TestALockedNameIsRefusedRegardlessOfWhetherThePasswordWasRight(t *testing.T) {
	// The property is asserted at the throttle and again at the login decision, because it is the
	// login decision's *ordering* that makes it true and either alone would let it be reverted.
	th := &Throttle{Max: 2, Window: 60 * time.Second}
	th.Failed("ada", at(0))
	th.Failed("ada", at(1))

	// Allow counts nothing, so it cannot be the thing that keeps the lock alive — and it still says
	// locked even though the caller is about to present the correct password.
	if !th.Allow("ada", at(2)).Locked {
		t.Fatal("the lock is not consulted before the password")
	}
	if !th.Allow("ada", at(2)).Locked {
		t.Fatal("consulting the lock twice cleared it")
	}
}

func TestTheLockLiftsWhenTheWindowCloses(t *testing.T) {
	th := &Throttle{Max: 2, Window: 60 * time.Second}
	th.Failed("ada", at(0))
	th.Failed("ada", at(1))

	if !th.Allow("ada", at(59)).Locked {
		t.Fatal("the lock lifted before the window closed")
	}
	if th.Allow("ada", at(61)).Locked {
		t.Fatal("the lock did not lift after the window closed")
	}
}

// The window runs from the failure that opened it, not from the most recent attempt — otherwise a
// script attempting once a second would extend its own lock forever and never learn anything, which
// sounds appealing and is actually a permanent denial of service against the real account holder.
func TestTheWindowRunsFromTheFirstFailureNotTheLast(t *testing.T) {
	th := &Throttle{Max: 2, Window: 60 * time.Second}
	th.Failed("ada", at(0))
	th.Failed("ada", at(30))

	verdict := th.Allow("ada", at(45))
	if !verdict.Locked {
		t.Fatal("not locked at 45s")
	}
	if verdict.RetryAfter != 15*time.Second {
		t.Fatalf("retry-after is %v, want 15s measured from the first failure", verdict.RetryAfter)
	}

	if th.Allow("ada", at(61)).Locked {
		t.Fatal("the window was extended by the second failure")
	}
}

func TestARetryAfterIsNeverZero(t *testing.T) {
	th := &Throttle{Max: 1, Window: 60 * time.Second}
	th.Failed("ada", at(0))

	// A moment before the window closes, the arithmetic would give something under a second.
	verdict := th.Allow("ada", at(59).Add(999*time.Millisecond))
	if !verdict.Locked {
		t.Fatal("not locked just before the window closes")
	}
	if verdict.RetryAfter < time.Second {
		t.Fatalf("retry-after is %v; a header saying 0 invites an immediate retry", verdict.RetryAfter)
	}
}

// §19: *The counter resets on success.*
func TestSuccessClearsTheCount(t *testing.T) {
	th := &Throttle{Max: 3, Window: 60 * time.Second}
	th.Failed("ada", at(0))
	th.Failed("ada", at(1))

	th.Succeeded("ada")

	if th.Tracked() != 0 {
		t.Fatalf("%d names are still tracked after a success", th.Tracked())
	}
	// Two more failures must not lock, because the count started again.
	th.Failed("ada", at(2))
	if th.Failed("ada", at(3)).Locked {
		t.Fatal("the count survived a successful sign-in")
	}
}

// §19: keyed on the **case-folded sanitised** username.
func TestTheCounterIsCaseFoldedSoChangingCaseDoesNotResetIt(t *testing.T) {
	th := &Throttle{Max: 3, Window: 60 * time.Second}
	th.Failed("ada", at(0))
	th.Failed("ADA", at(1))
	verdict := th.Failed("Ada", at(2))

	if !verdict.Locked {
		t.Fatal("three attempts under three spellings of one name did not lock it")
	}
	if th.Tracked() != 1 {
		t.Fatalf("three spellings created %d entries, want 1", th.Tracked())
	}
	if !th.Allow("aDa", at(3)).Locked {
		t.Fatal("a fourth spelling escaped the lock")
	}
}

func TestEveryNameOutsideThePatternSharesOneKey(t *testing.T) {
	th := &Throttle{Max: 2, Window: 60 * time.Second}

	// Two different hostile names, both sanitised to `?`.
	th.Failed("ada smith", at(0))
	th.Failed("grace\nhopper", at(1))

	if th.Tracked() != 1 {
		t.Fatalf("hostile names created %d entries; sanitising first is what bounds the table", th.Tracked())
	}
	if !th.Allow("anything invalid at all", at(2)).Locked {
		t.Fatal("the shared key for unsanitisable names is not locked")
	}
}

// §19: *At most **4096** distinct usernames are tracked, oldest evicted.*
func TestTheTableIsBoundedAtFourThousandAndNinetySixWithTheOldestEvicted(t *testing.T) {
	th := &Throttle{Max: 2, Window: time.Hour}

	// The first name fails twice, so it is locked, and then gets pushed out by 4096 others.
	th.Failed("ada", at(0))
	th.Failed("ada", at(0))
	if !th.Allow("ada", at(1)).Locked {
		t.Fatal("ada is not locked to begin with")
	}

	for i := 0; i < MaxThrottleKeys; i++ {
		th.Failed("user"+itoa(i), at(2))
	}

	if th.Tracked() > MaxThrottleKeys {
		t.Fatalf("%d names tracked, cap is %d", th.Tracked(), MaxThrottleKeys)
	}
	if th.Allow("ada", at(3)).Locked {
		t.Fatal("the oldest entry survived the cap, so the table is not bounded by eviction")
	}
	// The newest entry is still there, which is what *oldest evicted* means.
	if _, ok := th.entries[ThrottleKey("user"+itoa(MaxThrottleKeys-1))]; !ok {
		t.Fatal("the newest entry was evicted instead of the oldest")
	}
}

func TestAZeroMaxThrottlesNothing(t *testing.T) {
	th := &Throttle{Window: 60 * time.Second}

	for i := 0; i < 50; i++ {
		if th.Failed("ada", at(i)).Locked {
			t.Fatal("a throttle with no maximum locked a name")
		}
	}
	if th.Tracked() != 0 {
		t.Fatal("a disabled throttle is still keeping a table")
	}
}

func TestTwoNamesAreCountedSeparately(t *testing.T) {
	th := &Throttle{Max: 2, Window: 60 * time.Second}
	th.Failed("ada", at(0))
	th.Failed("ada", at(1))

	if th.Allow("grace", at(2)).Locked {
		t.Fatal("locking one name locked another; the lock is on the name")
	}
}

func TestSucceedingForAnUntrackedNameDoesNothing(t *testing.T) {
	th := &Throttle{Max: 2, Window: 60 * time.Second}
	th.Failed("ada", at(0))

	th.Succeeded("grace")

	if th.Tracked() != 1 {
		t.Fatalf("clearing an untracked name changed the table to %d entries", th.Tracked())
	}
}

func TestManyConcurrentAttemptsDoNotRaceOrStrandTheTable(t *testing.T) {
	th := &Throttle{Max: 3, Window: time.Minute}

	done := make(chan struct{})
	for i := 0; i < 16; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			name := "user" + itoa(i%4)
			for n := 0; n < 50; n++ {
				th.Failed(name, at(n))
				th.Allow(name, at(n))
				if n%10 == 0 {
					th.Succeeded(name)
				}
			}
		}(i)
	}
	for i := 0; i < 16; i++ {
		<-done
	}

	if th.Tracked() > 4 {
		t.Fatalf("four names produced %d entries", th.Tracked())
	}
}
