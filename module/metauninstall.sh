# The LKM is deliberately left loaded: the module trees stay mounted until the
# next reboot, and dropping magic_hide now would expose every one of them
# (stat/mountinfo would report the real state) for the rest of the session.
# Nothing of ours survives in /data, so no cleanup is needed here.
exit 0
