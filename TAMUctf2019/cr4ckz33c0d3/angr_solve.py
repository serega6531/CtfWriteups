import angr
b = angr.Project("./prodkey")
state = b.factory.blank_state(addr=0x400DFC)
sm = b.factory.simulation_manager(state)
sm.explore(find=0x400E4E)
found = sm.found[0]
print(base64.b64encode(found.posix.dumps(0)))
