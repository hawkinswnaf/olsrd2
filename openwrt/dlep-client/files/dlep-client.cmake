###############################
#### Generic configuration ####
###############################

# set CMAKE build type for application, api and plugins
# (Debug, Release, MinSizeRel)
set (CMAKE_BUILD_TYPE Debug)

# remove logging level from application, core-api and plugins
set (OONF_REMOVE_DEBUG_LOGGING false)
set (OONF_REMOVE_INFO_LOGGING  false)
set (OONF_REMOVE_WARN_LOGGING  false)

# remove help texts from application, core-api and plugins
set (OONF_REMOVE_HELPTEXT false)

###########################################
#### Default Application configuration ####
###########################################

# set name of program the executable and library prefix
set (OONF_APP DLEP-Client)
set (OONF_EXE dlep-client)
set (OONF_LIBPREFIX dlepclient)

# set default configuration file, if not set it will be '/etc/<OONF_APP>.conf'
# on linux/bsd/osx and '<OONF_EXE>.conf' (replaced .exe with .conf)

# set (OONF_DEFAULT_CONF "/etc/dlep-client.conf")

# setup custom text before and after default help message
set (OONF_HELP_PREFIX "Activates DLEP-client application\\\\n")
set (OONF_HELP_SUFFIX "")

# setup custom text after version string
set (OONF_VERSION_TRAILER "Visit http://www.olsr.org\\\\n")

# set application version (e.g. 0.1.0)
set (OONF_VERSION 0.1.0)

# set static plugins (list of plugin names, separated by space/newline)
set (OONF_STATIC_PLUGINS cfgparser_compact cfgio_file dlep_client httptelnet)

# choose if framework should be linked static or dynamic
set (OONF_FRAMEWORD_DYNAMIC false)

# set to true to stop application running without root privileges (true/false)
set (OONF_NEED_ROOT false)

# set to true if the application needs to set ip routes for traffic forwarding
set (OONF_NEED_ROUTING false)

# set to true to link packetbb API to application
set (OONF_NEED_PACKETBB true)

# name of the libnl library
set (OONF_LIBNL nl-tiny)

####################################
#### PacketBB API configuration ####
####################################

# disallow the consumer to drop a tlv context
set (PBB_DISALLOW_CONSUMER_CONTEXT_DROP false)

# activate assets() to check state of the pbb write
# and prevent calling functions at the wrong time
set (PBB_WRITER_STATE_MACHINE true)

# activate several unnecessary cleanup operations
# that make debugging the API easier
set (PBB_DEBUG_CLEANUP true)

# activate rfc5444 address-block compression
set (PBB_DO_ADDR_COMPRESSION true)

# set to 1 to clear all bits in an address which are not included
# in the subnet mask
# set this to false to make interop tests!
set (PBB_CLEAR_ADDRESS_POSTFIX false)
