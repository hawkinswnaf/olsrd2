# set library parameters
SET (source "constant_metric.c")

# use generic plugin maker
oonf_create_app_plugin("constant_metric" ${source} "" "")
