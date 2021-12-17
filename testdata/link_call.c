#include "common.h"

// Declared, but not defined
int foo();

__section("socket") int link_call() {
    return foo();
}
