To run the interaction:
1. run 'python3 Bob.py' from bob.tar. The port to listen on can be specified with -p, and while the
program is verbose by default, it can be quieted with -q

2. run 'python3 Alice.py' from alice.tar. the port bob is on can be specified with -p, and the hostname
of bob (or ip address) must be specified with -H. The message to send can be specified with -m.