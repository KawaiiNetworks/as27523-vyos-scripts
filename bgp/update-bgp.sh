#!/bin/bash

wget -O /config/myapp/set-bgp.core.mci.atlas.projectk.org.sh https://github.com/KawaiiNetworks/vyos-scripts/releases/download/nightly/set-bgp.core.mci.atlas.projectk.org.sh
vbash /config/myapp/set-bgp.core.mci.atlas.projectk.org.sh | tee /config/myapp/set-bgp.log
rm /config/myapp/set-bgp.core.mci.atlas.projectk.org.sh