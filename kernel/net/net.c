#include <net/net.h>
#include <lib/dynarray.h>

DYNARRAY_NEW(struct nic *, nics);

void register_nic(struct nic* nic) {
    DYNARRAY_INSERT(nics, nic);
}
