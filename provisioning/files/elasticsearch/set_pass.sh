#!/bin/bash

echo `echo -e "y\n" | /usr/share/elasticsearch/bin/elasticsearch-reset-password -a -u elastic | grep "New value:" | awk '{ print $3 }'`

rm $(dirname $(readlink -f $0))/`basename "$(realpath $0)"`