import sys

out = []
for line in open(sys.argv[1], 'r') :
	line = line.split()
	if len(line[-1]) == 2 :
		out.append(line[-1])
print(" ".join(out))
print()
out = [int(x, 16) for x in out]

def dump(l) :
	print(" ".join(f"{x:02X}" for x in l))

i = 0
while i+2 < len(out) :
	l = out[i+2]
	dump(out[i: i+l+4])
	i += 4+l
