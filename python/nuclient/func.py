# Copyright(C) 2007 INL
# Written by Victor Stinner <victor.stinner@inl.fr>
#
# $Id$
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
"""
Python binding of nuclient library functions
"""

from ctypes import (cdll,
    c_char_p, c_int, c_ubyte,
    POINTER, Structure)

library = cdll.LoadLibrary('libnuclient.so')

#--------------------------------------------------------------------------
# Define nuauth_session_p and nuclient_error_p: pointer to fake structures

class nuauth_session_t(Structure):
    # Opaque structure, want don't need to know it
    pass
nuauth_session_p = POINTER(nuauth_session_t)

class nuclient_error_t(Structure):
    # Opaque structure, want don't need to know it
    pass
nuclient_error_p = POINTER(nuclient_error_t)

#--------------------------------------------------------------------------

# int nu_client_error_init(nuclient_error_t **err);
nu_client_error_init = library.nu_client_error_init
nu_client_error_init.argstype = (POINTER(nuclient_error_p),)
nu_client_error_init.restype = c_int

# void nu_client_error_destroy(nuclient_error_t *err);
nu_client_error_destroy = library.nu_client_error_destroy
nu_client_error_destroy.argstype = (POINTER(nuclient_error_p),)
nu_client_error_destroy.restype = None

# nuauth_session_t *nu_client_new(const char *username,
#                                 const char *password,
#                                 unsigned char diffie_hellman,
#                                 nuclient_error_t *err);
nu_client_new = library.nu_client_new
nu_client_new.argstype = (c_char_p, c_char_p, c_ubyte, nuclient_error_p)
nu_client_new.restype = nuauth_session_p

# int nu_client_global_init(nuclient_error_t *err);
nu_client_global_init = library.nu_client_global_init
nu_client_global_init.argstype = (nuclient_error_p,)
nu_client_global_init.restype = c_int

# void nu_client_global_deinit();
nu_client_global_deinit = library.nu_client_global_deinit
nu_client_global_deinit.argstype = None
nu_client_global_deinit.restype = None

# int nu_client_connect(nuauth_session_t * session,
#                       const char *hostname,
#                       const char *service,
#                       nuclient_error_t *err);
nu_client_connect = library.nu_client_connect
nu_client_connect.argstype = (nuauth_session_p, c_char_p, c_char_p, nuclient_error_p)
nu_client_connect.restype = c_int

# void nu_client_reset(nuauth_session_t * session);
nu_client_reset = library.nu_client_reset
nu_client_reset.argstype = (nuauth_session_p,)
nu_client_reset.restype = None

# void nu_client_delete(nuauth_session_t * session);
nu_client_delete = library.nu_client_delete
nu_client_delete.argstype = (nuauth_session_p,)
nu_client_delete.restype = None

# const char *nu_get_version();
nu_get_version = library.nu_get_version
nu_get_version.argstype = None
nu_get_version.restype = c_char_p

# int nu_check_version(const char *version);
nu_check_version = library.nu_check_version
nu_check_version.argstype = (c_char_p,)
nu_check_version.restype = c_int

# char *nu_get_home_dir();
nu_get_home_dir = library.nu_get_home_dir
nu_get_home_dir.argstype = None
nu_get_home_dir.restype = c_char_p

# const char *nu_client_strerror(nuclient_error_t *err);
nu_client_strerror = library.nu_client_strerror
nu_client_strerror.argstype = (nuclient_error_p,)
nu_client_strerror.restype = c_char_p

# int nu_client_check(nuauth_session_t *session, nuclient_error_t *err);
nu_client_check = library.nu_client_check
nu_client_check.argstype = (nuauth_session_p, nuclient_error_p)
nu_client_check.restype = c_int

# void nu_client_set_verbose(nuauth_session_t * session,
#                            unsigned char enabled);
nu_client_set_verbose = library.nu_client_set_verbose
nu_client_set_verbose.argstype = (nuauth_session_p, c_ubyte)
nu_client_set_verbose.restype = None

DEFAULT_PORT = 4129

__all__ = (
    "nuauth_session_p", "nuclient_error_p",
    "nu_get_version", "nu_check_version", "nu_get_home_dir",
    "nu_client_error_init", "nu_client_error_destroy",
    "nu_client_global_init", "nu_client_global_deinit",
    "nu_client_new", "nu_client_delete",
    "nu_client_connect", "nu_client_check",
    "nu_client_set_verbose",
    "nu_client_strerror",
    "DEFAULT_PORT",
)

