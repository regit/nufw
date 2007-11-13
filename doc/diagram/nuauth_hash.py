#!/usr/bin/python
#
# Copyright(C) 2007 INL
# Written by Eric Leblond <eric@inl.fr>
#
# Generate a graphviz graph of life of packet in connection hash
#
# Depends on gvgen: http://software.inl.fr/trac/trac.cgi/wiki/GvGen
#
# You can generate a png output, nuauth_hash.png, by running:
# python nuauth_hash.py | dot -onuauth_hash.png -Tpng

import gvgen

graph = gvgen.GvGen()
graph.smartmode = 1

state_list = ["AUTHREQ", "USERPCKT", "DONE", "COMPLETING", "READY"]

gstate = {}

for state in state_list:
    gstate[state] = graph.newItem(state)

# #158510: adding id
# #b5b5b0: ignoring
graph.styleAppend("transition", "color", "blue")

graph.styleAppend("adding_id", "color", "#158510")
#graph.styleAppend("adding_id", "fontsize", "11pt")
graph.styleAppend("adding_id", "fontcolor", "#158510")

graph.styleAppend("ignoring", "color", "#b5b5b0")
#graph.styleAppend("ignoring", "fontsize", "11pt")
graph.styleAppend("ignoring", "fontcolor", "#b5b5b0")

step = graph.newLink(gstate["AUTHREQ"], gstate["COMPLETING"], "USERPCKT")
graph.styleApply("transition", step)

step = graph.newLink(gstate["AUTHREQ"], gstate["AUTHREQ"], "AUTHREQ")
graph.styleApply("adding_id", step)

step = graph.newLink(gstate["USERPCKT"], gstate["COMPLETING"], "AUTHREQ")
graph.styleApply("transition", step)

step = graph.newLink(gstate["USERPCKT"], gstate["USERPCKT"], "USERPCKT")
graph.styleApply("ignoring", step)

step = graph.newLink(gstate["COMPLETING"], gstate["READY"], "COMPLETING")
graph.styleApply("transition", step)

step = graph.newLink(gstate["COMPLETING"], gstate["COMPLETING"], "AUTHREQ")
graph.styleApply("adding_id", step)

step = graph.newLink(gstate["COMPLETING"], gstate["COMPLETING"], "USERPCKT")
graph.styleApply("ignoring", step)

step = graph.newLink(gstate["READY"], gstate["READY"], "AUTHREQ")
graph.styleApply("adding_id", step)

step = graph.newLink(gstate["READY"], gstate["READY"], "USERPCKT")
graph.styleApply("ignoring", step)

step = graph.newLink(gstate["DONE"], gstate["DONE"], "AUTHREQ")
graph.styleApply("adding_id", step)

step = graph.newLink(gstate["DONE"], gstate["DONE"], "USERPCKT")
graph.styleApply("ignoring", step)

graph.dot()


