"""
Copyright(C) 2008 INL
Written by Victor Stinner <victor.stinner AT inl.fr>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

$Id: __init__.py 4489 2008-02-21 17:03:32Z haypo $
"""

from nucentral import Component
from nevow import rend, tags, loaders
from twisted.internet.defer import succeed
from nucentral.core.context import Context
from datetime import timedelta

class NuauthFragment(rend.Fragment):
    docFactory = loaders.xmlstr(
        '<div style="border: 1px solid black; margin: 1ex; padding: 0.5ex;" xmlns:nevow="http://nevow.com/ns/nevow/0.1">'
        +'<div nevow:render="users" />'
        +'<div nevow:render="uptime" />'
        +'</div>'
    )

    def __init__(self, nuauth):
        rend.Fragment.__init__(self)
        self.nuauth = nuauth

    def formatUser(self, user):
        return tags.li[u"%s from %s" % (user['name'], user['addr'])]

    def _render_users(self, users, ctx=None):
        data = []
        for user in users:
            data.append(self.formatUser(user))
        if users:
            data = tags.ul[data]
        else:
            data = tags.p[u"No user connected."]
        return ctx.tag[data]

    def error(self, err, ctx):
        err = err.getErrorMessage()
        return ctx.tag[tags.p[u"Error: %s" % err]]

    def render_command(self, ctx, command, render_func):
        defer = succeed(command)
        defer.addCallback(self.nuauth.command, nevow_ctx=ctx)
        defer.addCallback(render_func, ctx=ctx)
        defer.addErrback(self.error, ctx=ctx)
        return defer

    def _render_uptime(self, uptime, ctx):
        delta = timedelta(seconds=uptime['seconds'])
        msg = u"Server started at %s, running since %s" % (uptime['start'], delta)
        return ctx.tag[tags.p[msg]]

    def render_users(self, ctx, data):
        return self.render_command(ctx, "users", self._render_users)

    def render_uptime(self, ctx, data):
        return self.render_command(ctx, "uptime", self._render_uptime)

class NuauthWeb(Component):
    NAME = "nuauth_web"
    VERSION = "1.0"
    API_VERSION = 1

    def init(self, core):
        self.core = core

    def fragment_nuauth(self):
        return NuauthFragment(self)

    def command(self, command, nevow_ctx):
        context = Context()
        return self.core.callService(context, "nuauth", command)

