# set library parameters
SET (source "route_modifier.c")

# use generic plugin maker
oonf_create_app_plugin("route_modifier" ${source} "" "")
