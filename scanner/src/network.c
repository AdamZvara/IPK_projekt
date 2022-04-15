#include <stdlib.h>
#include <stdio.h>
#include "network.h"

void print_interfaces()
{
    struct if_nameindex *if_nidxs, *intf;

    if_nidxs = if_nameindex();
    if (if_nidxs != NULL) {
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++) {
            printf("%s\n", intf->if_name);
        }
        if_freenameindex(if_nidxs);
    }
}