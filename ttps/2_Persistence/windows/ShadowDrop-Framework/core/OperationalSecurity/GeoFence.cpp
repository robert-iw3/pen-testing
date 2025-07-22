#include "EnvValidator.h"
#include <Windows.h>
#include <winnls.h>

BOOL GeoFence::CheckGeoRestrictions() {
    if (!EnvValidator::IsPermittedGeo()) {
        return FALSE;
    }

    return CheckIPLocation();
}

BOOL GeoFence::CheckIPLocation() {
    // need implement actual IP-to-location check

    return TRUE;
}
